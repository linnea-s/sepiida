#!/usr/bin/python
# Copyright 2008-2011 Linnea Skogtvedt <linnea@linuxavdelingen.no>
#
# This file is part of Sepiida.
#
# Sepiida is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Sepiida is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Sepiida.  If not, see <http://www.gnu.org/licenses/>.

import gtk
import gobject
import base64
import re
import cStringIO
import locale
import gettext
import time
import struct
import subprocess
import os
import sys

try:
    import json
except ImportError:
    import simplejson as json

t = gettext.translation('sepiida-gtk', '/usr/share/locale', fallback=True)
t.install()
ngettext = t.ngettext

debug = os.environ.get('debug', '0') == '1'

class Server:
    def __init__(self, hostname):
        self.name = self.hostname = hostname
        self._process = None
        self._requests = {}
        self._reqID = 0
        self.connected = False
    
    def _readResponse(self, source, condition):
        prefix = self._process.stdout.read(4) # int32 prefix
        if not len(prefix):
            return False
        try:
            length = struct.unpack('!I', prefix)[0]
        except ValueError:
            print >>sys.stderr, 'got invalid data: %s' % prefix
        
        if debug:
            print 'length: %d' % length
        
        msg = self._process.stdout.read(length)
        if not len(msg):
            return False
        if debug:
            print 'read: %d' % len(msg)
            print >>sys.stderr, 'got data: %s' % msg
        try:
            data = json.loads(msg)
            rid = data['requestID']
            err = data.get('error', '')
            gobject.idle_add(self._requests[rid], self, data['data'], err,
                             priority=gobject.PRIORITY_HIGH)
            del self._requests[rid]
        except (ValueError, KeyError):
            print >>sys.stderr, 'got invalid data: %s' % msg
        return True
    
    def _IOErr(self, source, condition):
        # broken pipe, ssh exited
        self._process.wait()
        gobject.idle_add(self.errback, self, self._process.stderr.read())
        self.connected = False
        
        for sid in self.sourceIDs:
            gobject.source_remove(sid)
        return False
    
    def connect(self, callback, errback):
        self._reqID = 0
        self.connected = False
        self.errback = errback
        
        cmd = ['ssh', '-o', 'ConnectTimeout=6', self.hostname, 'sepiida-connect']
        self._process = process = subprocess.Popen(cmd, shell=False,
                                         stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE,
                                         preexec_fn=os.setsid)
        sid1 = gobject.io_add_watch(process.stdout, gobject.IO_IN, self._readResponse)
        sid2 = gobject.io_add_watch(process.stdout, gobject.IO_ERR | gobject.IO_HUP, self._IOErr)
        self.sourceIDs = [sid1, sid2]
    
        def cbHello(server, data, error=''):
            if error:
                gobject.idle_add(errback, self, _('Not authorized'))
                self._process.wait()
                
                for sid in self.sourceIDs:
                    gobject.source_remove(sid)
            else:
                self.connected = True
                gobject.idle_add(callback, self)
        
        self._requests[self._reqID] = cbHello
    
    def sendRequest(self, request, args, callback):
        """
        Send request to server.
        Args:
         * request - the request to send to the server
         * args - the arguments, usually a list of ukey dicts
         * callback - a function to call when a response is received
        """
        self._reqID += 1
        req = json.dumps(
                     {'request': request,
                      'args': args
                      }
                     )
        prefix = struct.pack('!I', len(req))
        if debug:
            print >>sys.stderr, 'sendRequest: sending %s' % req
        self._process.stdin.write(prefix)
        self._process.stdin.write(req) 
        
        self._requests[self._reqID] = callback
    
    def openLocalForward(self, localPort, remotePort):
        """
        Open local forwarding. ssh -L is not used because it requires opening
        a new connection, which can be very slow in some cases.
        If localPort is 0, a random port above 5900 is selected.
        Returns localPort.
        """
        import socket
        import random
        while localPort == 0:
            # Get a port above 5900, few VNC clients accept negative VNC
            # display numbers
            p = random.randint(6000, 30000)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.bind(('127.0.0.1', p))
                s.close()
                localPort = p
            except socket.error:
                pass
            
        p = subprocess.Popen(['socat', 'exec:ssh %s sepiida-connect-port %d' % (self.hostname, remotePort),
                              'tcp-listen:%d,rcvtimeo=10' % localPort],
                              shell=False, preexec_fn=os.setsid)
        gobject.child_watch_add(p.pid, lambda pid, condition: None) # avoid defunct process
        return localPort

class User(object):
    def __init__(self, server, username, userver, client, display):
        self.server = server
        self.username = username
        self.userver = userver
        self.client = client
        self.display = display
        self.location = ''
        self.name = ''
        self.groups = []
        self.lastupdate = 0
        self.ltime = -1
        self.ukey_t = (server, username, userver, client, display)
        self.ukey_d = { 'username': username, 'server': userver, 'client': client, 'display': display }
    

class GtkClient:
    def __init__(self, args=[]):
        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
        self.window.set_default_size(500, 480)
        self.window.set_title('Sepiida')
        self.window.connect('delete_event', self.delete_event)
        
        self.servers = []
        self.serverdict = {}
        self.users = {}

        accel_group = gtk.AccelGroup()
        self.window.add_accel_group(accel_group)
        accel_group.connect_group(ord('W'), gtk.gdk.CONTROL_MASK, 0, self.quit)
        clipboard = gtk.Clipboard()
        def copy(accel_group, acceleratable, keyval, modifier):
            treeselection = self.treeview.get_selection()
            ls = self.liststore
            def gen():
                for row in treeselection.get_selected_rows()[1]:
                    u = ls[row][-1]
                    yield '%s\t%s\t%s\t%s\t%s\t%s' % \
                    (u.username, u.client, u.userver, u.display, u.name, u.ltime)
            clipboard.set_text('\n'.join( gen() ))
        accel_group.connect_group(ord('C'), gtk.gdk.CONTROL_MASK, 0, copy)

        self.vbox = gtk.VBox(False, 0)
        self.window.add(self.vbox)
        
        self.notebook = gtk.Notebook()
        self.notebook.set_tab_pos(gtk.POS_TOP)
        self.vbox.pack_start(self.notebook)
        self.frame_users = gtk.Frame()
        self.frame_machines = gtk.Frame()
        self.notebook.append_page(self.frame_users, gtk.Label(_('Users')))
        self.notebook.append_page(self.frame_machines, gtk.Label(_('Machines')))

        scroll_users = gtk.ScrolledWindow()
        scroll_users.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        self.frame_users.add(scroll_users)

        scroll_machines = gtk.ScrolledWindow()
        scroll_machines.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        self.frame_machines.add(scroll_machines)
        
        # Users
        # menu
        self.context_menu = gtk.Menu()
        for item, callback in ((_('_Overview'), self.overview), (_('_Filter...'), self.filter),
        (_('_View/control...'), self.vnc), (_('Send _message...'), self.send_message),
        (_('_Log out user'), self.logout_user), (_('_Processes'), self.processes),
        (_('Loc_k screen'), self.lock_screen), (_('Open _URL...'), self.open_url)):
            menuitem = gtk.MenuItem(item)
            self.context_menu.append(menuitem)
            menuitem.connect('activate', callback)
            menuitem.show()
        # username, client, location, name, server, login time, display, Sepiida server, background colour, user object
        self.real_liststore = gtk.ListStore(str, str, str, str, str, str, str, str, str, object)
        self.filtered_liststore = self.real_liststore.filter_new()
        self.filtered_liststore.set_visible_func(self.matches_filter)
        self.liststore = gtk.TreeModelSort(self.filtered_liststore)
        
        self.treeview = gtk.TreeView(self.liststore)
        self.treeview_selection = self.treeview.get_selection()
        self.treeview_selection.set_mode(gtk.SELECTION_MULTIPLE)
        self.treeview.connect('button_press_event', self.treeview_button_press, self.context_menu)
        self.treeview.set_search_column(0)
        def select_all(*ignored):
            self.treeview_selection.select_all()
        self.treeview.connect('row-activated', select_all)
        
        for index, header in enumerate([_('Username'), _('Client'), _('Location'), _('Name'), _('Server'), _('Login time')]):
            treeviewcol = gtk.TreeViewColumn(header)
            self.treeview.append_column(treeviewcol)
            cellrenderer = gtk.CellRendererText()
            treeviewcol.pack_start(cellrenderer)
            treeviewcol.set_attributes(cellrenderer, text=index, background=8)
            treeviewcol.set_resizable(True)
            treeviewcol.set_sort_column_id(index)
        self.treeview.set_search_column(0)
        self.real_liststore.set_sort_column_id(0, gtk.SORT_ASCENDING)        

        scroll_users.add(self.treeview)
        
        # Machines
        self.machines_liststore = gtk.ListStore(str, str, str, str, str, str, str)
        self.machines_treeview = gtk.TreeView(self.machines_liststore)
        for index, header in enumerate([_('Sepiida server'), _('Server/workstation'), _('Users'), _('Load'), _('Uptime'), _('Operating system'), _('Location')]):
            treeviewcol = gtk.TreeViewColumn(header)
            self.machines_treeview.append_column(treeviewcol)
            cellrenderer = gtk.CellRendererText()
            treeviewcol.pack_start(cellrenderer)
            treeviewcol.set_attributes(cellrenderer, text=index)
            treeviewcol.set_sort_column_id(index)
            treeviewcol.set_resizable(True)
        self.machines_treeview.set_search_column(1)
        self.machines_liststore.set_sort_column_id(0, gtk.SORT_ASCENDING)
        machines_treeview_selection = self.machines_treeview.get_selection()
        machines_treeview_selection.set_mode(gtk.SELECTION_MULTIPLE)
        
        machines_context_menu = gtk.Menu()
        for item, callback in ((_('_Login'), self.login),
                               (_('_Shutdown'), self.shutdown),
                               (_('_Reboot'), self.reboot)):
            menuitem = gtk.MenuItem(item)
            machines_context_menu.append(menuitem)
            menuitem.connect('activate', callback)
            menuitem.show()
        self.machines_treeview.connect('button_press_event', self.treeview_button_press, machines_context_menu)

        scroll_machines.add(self.machines_treeview)

        # filter
        self.filter_liststore = gtk.ListStore(str, str)
        self.filter_treeview = gtk.TreeView(self.filter_liststore)
        
        # the value here refers either to the index in self.liststore,
        # or to the attribute name in the user object
        
        attribute_choices = ((_('Username'), 0), (_('Group'), 'groups'),
            (_('Client'), 1), (_('Server'), 4), (_('Name'), 3),
            (_('Location'), 2))
        self.attribute_choices_dict = dict(attribute_choices)

        combomodel_attribute = gtk.ListStore(str)
        for opt, key in attribute_choices:
            combomodel_attribute.append([opt])

        def cell_edited(cellrenderertext, path, new_text, index):
            iter_ = self.filter_liststore.get_iter(path)
            self.filter_liststore.set_value(iter_, index, new_text)

        filter_cell1 = gtk.CellRendererCombo()
        filter_cell1.connect('edited', cell_edited, 0)
        filter_cell1.set_property('text-column', 0)
        filter_cell1.set_property('has-entry', False)
        filter_cell1.set_property('model', combomodel_attribute)
        filter_cell1.set_property('editable', True)
        filter_cell3 = gtk.CellRendererText()
        filter_cell3.connect('edited', cell_edited, 1)
        filter_cell3.set_property('editable', True)
        
        self.filter_tvcolumn1 = gtk.TreeViewColumn(_('Attribute'))
        self.filter_tvcolumn3 = gtk.TreeViewColumn(_('Value'))

        self.filter_treeview.append_column(self.filter_tvcolumn1)
        self.filter_treeview.append_column(self.filter_tvcolumn3)

        self.filter_tvcolumn1.pack_start(filter_cell1, True)
        self.filter_tvcolumn3.pack_start(filter_cell3, True)
        self.filter_tvcolumn1.set_attributes(filter_cell1, text=0)
        self.filter_tvcolumn3.set_attributes(filter_cell3, text=1)

        self.filter_vbox = filter_vbox = gtk.VBox(False)
        filter_vbox.pack_start(self.filter_treeview)

        def on_filter_add_clicked(button):
            iter_ = self.filter_liststore.append((attribute_choices[0][0], ''))
            gobject.idle_add(self.filter_treeview.get_selection().select_iter, iter_)

        def on_filter_remove_clicked(button):
            model, iter_ = self.filter_treeview.get_selection().get_selected()
            if not iter_: return
            self.filter_liststore.remove(iter_)

        filter_ar_hbox = gtk.HBox(False)
        filter_add = gtk.Button()
        filter_add.connect('clicked', on_filter_add_clicked)
        filter_add.add(gtk.image_new_from_stock(gtk.STOCK_ADD, gtk.ICON_SIZE_SMALL_TOOLBAR))
        filter_remove = gtk.Button()
        filter_remove.connect('clicked', on_filter_remove_clicked)
        filter_remove.add(gtk.image_new_from_stock(gtk.STOCK_REMOVE, gtk.ICON_SIZE_SMALL_TOOLBAR))
        filter_ar_hbox.pack_start(filter_add, False, False)
        filter_ar_hbox.pack_start(filter_remove, False, False)

        self.filter_invert_checkbutton = gtk.CheckButton(label=_('Invert'))
        filter_vbox.pack_start(self.filter_invert_checkbutton, False, False)

        filter_vbox.pack_start(filter_ar_hbox, False, False)

        #
        self.statusbar = gtk.Statusbar()
        self.vbox.pack_start(self.statusbar, False, False)
        #
        gobject.idle_add(self.config, args)

        self.window.show_all()
        gtk.main()
    
    def config(self, args):
        if not args:
            dlg = gtk.Dialog(_('Connect'), self.window,
            gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT,
            (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL, gtk.STOCK_OK, gtk.RESPONSE_ACCEPT))
            entry = gtk.Entry()
            entry.connect('activate', lambda *args: dlg.response(gtk.RESPONSE_ACCEPT))
            dlg.vbox.pack_start(gtk.Label(_('SSH host/alias:')))
            dlg.vbox.pack_start(entry)
            dlg.show_all()
            response = dlg.run()
            dlg.destroy()

            if response != gtk.RESPONSE_ACCEPT:
                self._quit()
                return
            servers = entry.get_text().split()
        else:
            servers = args
        
        for name in servers:
            self.connect(name)
    
    def connect(self, hostname):
        def update_title():
            self.window.set_title('Sepiida - %s' % (', '.join([server.name for server in self.servers if server.connected])))
        
        def prompt_reconnect(server, error):
            dlg = gtk.Dialog(_('Connection failed'), self.window,
                             gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT,
                             (gtk.STOCK_NO, gtk.RESPONSE_NO, gtk.STOCK_YES, gtk.RESPONSE_YES))
            dlg.vbox.pack_start(gtk.Label(_('Connection to %s failed: %s') % (server.name, error)))
            dlg.vbox.pack_start(gtk.Label(_('Do you want to reconnect?')))
            dlg.show_all()
            response = dlg.run()
            dlg.destroy()
            if response == gtk.RESPONSE_YES:
                gobject.idle_add(self.connect, server.name)
                
        def eb_connect(server, error):
            try:
                gobject.source_remove(server.timeout_id)
            except AttributeError:
                pass
            for key, user in self.users.items():
                if user.server is server:
                    self.real_liststore.remove(user.iter)
                    del self.users[key]
                    self.highlight_duplicate(user.username)
            iter = self.machines_liststore.get_iter_first()
            while iter:
                if self.machines_liststore.get(iter, 0)[0] == server.hostname:
                    self.machines_liststore.remove(iter)
                iter =  self.machines_liststore.iter_next(iter)
            self.update_statusbar()
            prompt_reconnect(server, error)
            
        def cb_connect(server):
            update_title()
            server.timeout_id = gobject.timeout_add(10000, self.refresh, server)
            self.refresh(server)
        
        try:
            server = self.serverdict[hostname]
        except KeyError:
            server = Server(hostname)
            self.servers.append(server)
            self.serverdict[hostname] = server
        
        server.connect(cb_connect, eb_connect)
 
    def update_statusbar(self):
        total_users = len(self.real_liststore)
        total_shown = len(self.liststore)
        total_machines = len(self.machines_liststore)
        context_id = self.statusbar.get_context_id('Refresh')
        msg_users = ngettext(
                       '%(total_users)d user logged in, %(total_shown)d shown',
                       '%(total_users)d users logged in, %(total_shown)d shown',
                       total_users) % locals()
        msg_machines = ngettext(
                        '%(total_machines)d machine',
                        '%(total_machines)d machines',
                        total_machines) % locals()
        status_msg = _('%(msg_users)s, %(msg_machines)s') % locals()
        self.statusbar.push(context_id, status_msg)
    
    def highlight_duplicate(self, username):
        """
        Check if a user is logged in twice or more, and if so highlight the rows.
        """
        uobjs = [u for u in self.users.itervalues() if u.username == username]
        if len(uobjs) > 1:
            bgcolor = 'yellow'
        else:
            bgcolor = None
        
        for user in uobjs:
            self.real_liststore.set(user.iter, 8, bgcolor)        
        
    def refresh(self, server):
        total_users = 0
        total_filtered = 0
            
        def cbUsers(server, data, error=''):
            # NOTE: server.name != userver
            # server is the Sepiida server, userver is the server/workstation the user is working on
            server.lastupdate = int(time.time())
            localtime = time.localtime()
            for udict in data:
                username = udict['username']
                userver = udict['server']
                client = udict['client']
                display = udict['display']
                name = udict['name']
                groups = udict['groups']
                ltime = udict['time']
                location = udict.get('location', '')

                ukey_t = (server, username, userver, client, display)
                try:
                    user = self.users[ukey_t]
                except KeyError:
                    user = User(server, username, userver, client, display)
                    t = time.localtime(ltime)
                    if localtime[:3] != t[:3]:
                        user.ltime = time.strftime('%b %d %H:%M', t)
                    else:
                        user.ltime = time.strftime('%H:%M', t)
                    user.iter = self.real_liststore.append((username, client, '', name, userver, user.ltime, display, server.name, None, user))
                    self.users[ukey_t] = user
                    self.highlight_duplicate(user.username)
                user.lastupdate = int(time.time())
                user.name = name
                user.groups = groups
                user.location = location
                for val, col in ((user.name, 3), (user.location, 2)):
                    if val != self.real_liststore.get(user.iter, col):
                        self.real_liststore.set(user.iter, col, val)
            
            for ukey_t, user in self.users.items():
                if user.server is server:
                    if user.lastupdate < server.lastupdate:
                        # user logged out
                        self.real_liststore.remove(user.iter)
                        del self.users[ukey_t]
                        self.highlight_duplicate(user.username)
            
            gobject.idle_add(self.update_statusbar)
        
        def cbServers(server, data, error=''):
            ls = self.machines_liststore
            # {userver: treeiter}
            map = dict([(ls[i][1], ls.get_iter(i)) for i in xrange(len(ls)) if ls[i][0] == server.hostname])
            
            for d in data:
                userver = d['server']
                nusers = d['users']
                load = '%1.2f' % d['load']
                platform = d.get('os', '')
                location = d.get('location', '')
                
                # in 0.5, "uptime" is the boot time in unix time
                if d['uptime'] > 1262277000: # 40 years
                    uptime = time.time() - d['uptime']
                else:
                    uptime = d['uptime']
                days, r = divmod(uptime, 86400)
                hours, r = divmod(r, 3600)
                minutes, r = divmod(r, 60)
                
                # 1d 10h 24m
                uptime = _('%(days)dd %(hours)dh %(minutes)dm') % locals()
                # Columns:
                # Sepiida server, user server/ws, N users, Load, Uptime, OS, Location
                try:
                    it = map[userver]
                except KeyError:
                    it = self.machines_liststore.append((server.hostname, userver, '', '', '', '', ''))
                    map[userver] = it
                ls.set(it, 2, str(nusers))
                ls.set(it, 3, load)
                ls.set(it, 4, uptime)
                ls.set(it, 5, platform)
                ls.set(it, 6, location)
            
            offline = set(map.iterkeys()) - set((d['server'] for d in data))
            for userver in offline:
                it = map[userver]
                ls.remove(it)
            
        server.sendRequest('listUsers', [], cbUsers)
        server.sendRequest('listServers', [], cbServers)
        return True

    def delete_event(self, widget, event, data=None):
        self._quit()
        return False
    def _quit(self):
        gtk.main_quit()
    def close(self):
        pass

    def quit(self, accel_group, acceleratable, keyval, modifier):
        self.window.destroy()
        self._quit()
        return True
    
    def treeview_button_press(self, treeview, event, menu):
        """
        Pop up context menu over treeview.
        """
        if event.button == 3:
            try:
                path, col, cellx, celly = treeview.get_path_at_pos(int(event.x), int(event.y))
            except TypeError: pass
            else:
                treeview.grab_focus()
                selection = treeview.get_selection()

                if not selection.path_is_selected(path):
                    selection.unselect_all()
                    selection.select_path(path[0])

            menu.popup(None, None, None, event.button, event.time)
            return True
    
    def get_selected(self):
        """
        Returns a dict indexed by server with a list of ukeys
        """
        n_users = 0
        selected = {}
        selection = self.treeview.get_selection()
        for row in selection.get_selected_rows()[1]:
            user = self.liststore[row][-1]
            server = user.server
            ukey = user.ukey_d.copy()
            try:
                selected[server].append(ukey)
            except KeyError:
                selected[server] = [ ukey ]
            n_users += 1
        return n_users, selected
    def get_selected_machines(self):
        """
        Returns a dict indexed by Sepiida server containing a list of selected
        machines.
        """
        n = 0
        selection = self.machines_treeview.get_selection()
        selected = {}
        for row in selection.get_selected_rows()[1]:
            server = self.serverdict[self.machines_liststore[row][0]]
            userver = self.machines_liststore[row][1]
            try:
                selected[server].append(userver)
            except KeyError:
                selected[server] = [ userver ]
            n += 1
        return n, selected
    
    def entry_dialog(self, cb, title, prompt, re_validate, initialtext=''):
        dlg = gtk.Dialog(title, None,
        gtk.DIALOG_DESTROY_WITH_PARENT,
        (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL, gtk.STOCK_OK, gtk.RESPONSE_ACCEPT))
        entry = gtk.Entry()
        entry.set_text(initialtext)
        red = gtk.gdk.color_parse('red')
        def validate(entry):
            if re_validate.search(entry.get_text()):
                entry.modify_base(gtk.STATE_NORMAL, None)
                dlg.set_response_sensitive(gtk.RESPONSE_ACCEPT, True)
            else:
                entry.modify_base(gtk.STATE_NORMAL, red)
                dlg.set_response_sensitive(gtk.RESPONSE_ACCEPT, False)
        entry.connect('changed', validate)
        gobject.idle_add(validate, entry)
        dlg.vbox.pack_start(gtk.Label(prompt))
        dlg.vbox.pack_start(entry)
        
        def close(dialog, data=None):
            dialog.destroy()
        def response(dialog, response_id, data=None):
            if response_id == gtk.RESPONSE_ACCEPT:
                gobject.idle_add(cb, entry.get_text())
            dialog.destroy()
            
        dlg.connect('close', close)
        dlg.connect('response', response)
        dlg.show_all()
    
    def send_message(self, widget, selected=None):
        n, selected = selected or self.get_selected()
        if n < 1:
            return
        
        def cbText(message):    
            def cb(server, data, error=''):
                pass
            
            for server, args in selected.iteritems():
                for arg in args:
                    arg['message'] = message
                server.sendRequest('sendMessage', args, cb)
            
        self.entry_dialog(cbText, _('Send message'), _('Message:'), re.compile('\S+'))
        
    def open_url(self, widget, selected=None):
        n, selected = selected or self.get_selected()
        if n < 1:
            return
        def cbText(url):
            def cbOpened(server, data, error=''):
                return
            for server, args in selected.iteritems():
                for arg in args:
                    arg['url'] = url
                server.sendRequest('openURL', args, cbOpened)
        self.entry_dialog(cbText, _('Open URL'), _('URL:'), re.compile('^\w+://\S+'), 'http://')
    
    def logout_user(self, widget, selected=None):
        n, selected = selected or self.get_selected()
        if n < 1:
            return
        def cbConfirmed(selected):
            def cbLoggedout(server, data, error=''):
                pass
            
            for server, args in selected.iteritems():
                server.sendRequest('logout', args, cbLoggedout)
        
        self.confirm(cbConfirmed, selected, _('Log out users'),
                            ngettext('Log out %(n_users)d user?','Log out %(n_users)d users?', n) % {'n_users': n})
    
    def confirm(self, cbOK, selected, title, message):
        import textwrap
        def users():
            for args in selected.itervalues():
                for udict in args:
                    yield udict['username']
        dlg = gtk.Dialog(title, None,
        gtk.DIALOG_DESTROY_WITH_PARENT,
        (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL, gtk.STOCK_OK, gtk.RESPONSE_ACCEPT))
        dlg.vbox.pack_start(gtk.Label(message))
        userlist = '\n'.join(textwrap.wrap(', '.join(users()), width=80))
        dlg.vbox.pack_start(gtk.Label(userlist))
        
        def close(dialog, data=None):
            dialog.destroy()
        def response(dialog, response_id, data=None):
            if response_id == gtk.RESPONSE_ACCEPT:
                gobject.idle_add(cbOK, selected)
            dialog.destroy()
            
        dlg.connect('close', close)
        dlg.connect('response', response)
        dlg.show_all()  
    
    def lock_screen(self, widget, selected=None):
        n, selected = selected or self.get_selected()
        if n < 1:
            return
        def cbConfirmed(selected):
            def cbLocked(server, data, error=''):
                pass
            for server, args in selected.iteritems():
                server.sendRequest('lockScreen', args, cbLocked)
        
        self.confirm(cbConfirmed, selected, _('Lock screen'),
                            ngettext('Lock screen of %(n_users)d user?', 'Lock screens of %(n_users)d users?', n) % {'n_users': n})
    
    def vnc(self, widget, selected=None):
        n, selected = selected or self.get_selected()
        if n != 1:
            return
        
        server, ukeys = selected.items()[0]
        ukey_d = ukeys[0]
        user = ukey_d['username']
        client = ukey_d['client']
        userver = ukey_d['server']

        dlg = gtk.Dialog(_('View/control (%s@%s@%s)') % (user, client, userver), self.window,
        gtk.DIALOG_DESTROY_WITH_PARENT,
        (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL))
        im = gtk.Image()
        im.set_size_request(320, 240)
        dlg.vbox.pack_start(im)
        label = gtk.Label(_('Please wait...'))
        dlg.vbox.pack_start(label)
        vncstatus = gtk.Label()
        dlg.vbox.pack_start(vncstatus)

        control = gtk.Button(label=_('_Control'))
        dlg.action_area.pack_start(control)
        view = gtk.Button(label=_('_View'))
        dlg.action_area.pack_start(view)

        def fetch_thumb(data=None):
            def cbThumb(server, data, error=''):
                pbl = gtk.gdk.PixbufLoader()
                try:
                    pbl.write(base64.b64decode(data[0].get('thumbnail', '')))
                    pbl.close()
                except (TypeError, gobject.GError):
                    label.set_text(_('Got invalid image data'))
                    return False
                pixbuf = pbl.get_pixbuf()
                im.set_from_pixbuf(pixbuf)
                
                label.hide()
            server.sendRequest('getThumbnails', [ukey_d], cbThumb)
            return False

        def control_view(button, viewonly):
            def cbStatus(status):
                if status:
                    vncstatus.set_text(status)
            def cbVnc(server, data, error=''):
                if error or data[0].get('error', ''):
                    vncstatus.set_text(_('Failed'))
                    return
                self.handleVnc(server, data[0]['port'], data[0].get('protocol', 'vnc'), cbStatus,
                               viewonly, data[0].get('password', None))

            vncstatus.set_text(_('Sending request...'))
            server.sendRequest('vnc', [ukey_d], cbVnc)
        
        control.connect('clicked', control_view, False)
        view.connect('clicked', control_view,  True)

        def response(dialog, response_id=None, data=None):
            dialog.destroy()
             
        dlg.connect('close', response)
        dlg.connect('response', response)
        dlg.show_all()
        gobject.idle_add(fetch_thumb)
    def filter(self, widget, event=None):
        dlg = gtk.Dialog(_('Filter'), self.window,
        gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT,
        (gtk.STOCK_CLOSE, gtk.RESPONSE_CLOSE))
        dlg.set_size_request(370, 300)

        dlg.vbox.pack_start(self.filter_vbox)
        dlg.show_all()
        dlg.run()
        dlg.vbox.remove(self.filter_vbox)
        dlg.destroy()
        
        self.filtered_liststore.refilter()
        gobject.idle_add(self.update_statusbar)

    def matches_filter(self, model, iter, user_data=None):
        if not len(self.filter_liststore):
            # no matching criteria
            return True
        invert = self.filter_invert_checkbutton.get_active()
        for attr, val_match in self.filter_liststore:
            attr = self.attribute_choices_dict[attr]
            try:
                val_user = model[iter][attr]
            except TypeError: # attr is not a index, but a userobj attribute
                user = model[iter][-1]
                if user is None:
                    return False # why does this happen?
                val_user = getattr(user, attr)
            #print attr, val_match, val_user
            
            def contains(a, b):
                return a.lower() in b.lower()
            
            if val_user is None: # why does this happen?
                return False
            elif type(val_user) is list:
                if invert ^ any((contains(val_match, x) for x in val_user)):
                    return True
            elif invert ^ contains(val_match, val_user):
                return True
        return False
    
    def overview(self, widget=None, event=None):
        n, selected = self.get_selected()
        if n < 1:
            return
        treeselection = self.treeview.get_selection()
        # preserve ordering from user list
        selected_flat = [ self.liststore[r][-1]
                         for r in treeselection.get_selected_rows()[1] ]

        RESPONSE_REFRESH = gtk.RESPONSE_OK
        dlg = gtk.Dialog(_('Overview'), None,
            gtk.DIALOG_DESTROY_WITH_PARENT,
            (gtk.STOCK_CLOSE, gtk.RESPONSE_CANCEL,
            gtk.STOCK_REFRESH, RESPONSE_REFRESH))
        dlg.set_default_size(995, 588)
        dlg.show_all()
        updated = gtk.Label()
        dlg.action_area.pack_start(updated)
        dlg.action_area.reorder_child(updated, 0)

        scrolled_window = gtk.ScrolledWindow()
        scrolled_window.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        dlg.vbox.pack_start(scrolled_window)
        
        def create_menu(user, eventbox):
            context_menu = gtk.Menu()
            selected = 1, { user.server: [ user.ukey_d.copy() ] }
            for item, callback in ((_('_View/control...'), self.vnc),
                                   (_('Send _message...'), self.send_message),
                                   (_('_Log out user'), self.logout_user),
                                   (_('_Processes'), self.processes),
                                   (_('Loc_k screen'), self.lock_screen),
                                   (_('Open _URL...'), self.open_url)):
                menuitem = gtk.MenuItem(item)
                context_menu.append(menuitem)
                menuitem.connect('activate', callback, selected)
                menuitem.show()
            
            def button_press(widget, event):
                if event.button == 3:
                    context_menu.popup(None, None, None, event.button, event.time)
                    return True
            
            eventbox.connect('button_press_event', button_press)
            
        maxcol = 3
        rows = (len(selected) / maxcol) or 1
        table = gtk.Table(rows, maxcol, True)
        table.set_row_spacings(2)
        table.set_col_spacings(2)
        scrolled_window.add_with_viewport(table)
        table.show()

        row = 0
        col = 0
        images = {}
        for user in selected_flat:
            im = gtk.Image()
            im.set_size_request(320, 240)
            eb = gtk.EventBox()
            vb = gtk.VBox(False)
            eb.add(vb)
            vb.pack_start(im, False, False)
            vb.pack_start(gtk.Label('%s@%s@%s' % (
                                                  user.username,
                                                  user.client,
                                                  user.userver)),
                                                  False, False)
            images[user] = im
            create_menu(user, eb)

            table.attach(eb, col, col+1, row, row+1)
            col += 1
            if col == maxcol:
                row += 1
                col = 0
        
        def updateImages(server, data, error=''):
            for ukey_d in data:
                ukey_t = (server, ukey_d['username'], ukey_d['server'],
                          ukey_d['client'], ukey_d['display'])
                try:
                    im = images[self.users[ukey_t]]
                except KeyError: # user logged out
                    continue
                pbl = gtk.gdk.PixbufLoader()
                try:
                    pbl.write(base64.b64decode(ukey_d.get('thumbnail', '')))
                    pbl.close()
                    im.set_from_pixbuf(pbl.get_pixbuf())
                except gobject.GError:
                    continue
            updated.set_text(time.strftime(_('Last updated: %H:%M:%S')))
            
        def refresh():
            for im in images.itervalues():
                im.set_from_pixbuf(None)
                
            for server, ukeys in selected.iteritems():
                for ukey in ukeys:
                    server.sendRequest('getThumbnails', [ukey], updateImages)

        def close(dialog, data=None):
            dialog.destroy()
        def response(dialog, response_id, data=None):
            if response_id == RESPONSE_REFRESH:
                gobject.idle_add(refresh)
            else:
                dialog.destroy()
             
        dlg.connect('close', close)
        dlg.connect('response', response)
        dlg.show_all()
        gobject.idle_add(refresh)

    def processes(self, widget=None, selected=None):
        n, selected = selected or self.get_selected()
        if n < 1:
            return

        RESPONSE_REFRESH = 1
        dlg = gtk.Dialog(_('Processes'), None,
            gtk.DIALOG_DESTROY_WITH_PARENT,
            (gtk.STOCK_CLOSE, gtk.RESPONSE_CANCEL,
            gtk.STOCK_REFRESH, RESPONSE_REFRESH))
        dlg.set_default_size(645, 520)

        scrolled_window = gtk.ScrolledWindow()
        scrolled_window.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        dlg.vbox.pack_start(scrolled_window)
        # user, client, pid, commandline, userver (not shown), display (not shown), servername
        proc_liststore = gtk.ListStore(str, str, str, str, str, str, str)
        proc_treeview = gtk.TreeView(proc_liststore)
        treeview_selection = proc_treeview.get_selection()
        treeview_selection.set_mode(gtk.SELECTION_MULTIPLE)
        for index, header in enumerate((_('Username'), _('Client'), _('PID'), _('Command line'))):
            treeviewcol = gtk.TreeViewColumn(header)
            proc_treeview.append_column(treeviewcol)
            cellrenderer = gtk.CellRendererText()
            treeviewcol.pack_start(cellrenderer)
            treeviewcol.set_attributes(cellrenderer, text=index)
            treeviewcol.set_sort_column_id(index)
        proc_treeview.set_search_column(3)

        scrolled_window.add(proc_treeview)

        def close(dialog, data=None):
            dialog.destroy()
        
        def cbHandleResponse(server, data, error=''):
            #print server, data
            for ukey_d in data:
                if not ukey_d.get('processes', ''):
                    # TODO: this probably means that the user is offline
                    continue
                username = ukey_d['username']
                client = ukey_d['client']
                userver = ukey_d['server']
                display = ukey_d['display']
                
                for pid, commandline in ukey_d['processes']:
                    proc_liststore.append((username, client, pid, commandline, userver, display, server.name))
        
        def refresh():
            proc_liststore.clear()
            for server, userlist in selected.iteritems():
                # userlist is already a list of ukeys, which is what the server expects
                args = userlist
                server.sendRequest('listProcesses', args, cbHandleResponse)

        def kill_processes(widget=None, event=None):
            args_d = {}
            selection = treeview_selection
            for row in selection.get_selected_rows()[1]:
                user = proc_liststore[row][0]
                client = proc_liststore[row][1]
                pid = proc_liststore[row][2]
                userver = proc_liststore[row][4]
                server = self.serverdict[proc_liststore[row][6]]
                display = proc_liststore[row][5]
                
                arg = {'username': user, 'server': userver,
                       'client': client, 'display': display, 'pid': pid}
                
                try:
                    args_d[server].append(arg)
                except KeyError:
                    args_d[server] = [ arg ]
            
            for server, args in args_d.iteritems():
                def ign(server, data, error=''):
                    pass
                server.sendRequest('killProcesses', args, ign)
            
        context_menu = gtk.Menu()
        for item, callback in ((_('End processes'), kill_processes),):
            menuitem = gtk.MenuItem(item)
            context_menu.append(menuitem)
            menuitem.connect('activate', callback)
            menuitem.show()

        def response(dialog, response_id, data=None):
            if response_id == RESPONSE_REFRESH:
                gobject.idle_add(refresh)
            else:
                dialog.destroy()

        def treeview_button_press(treeview, event):
            if event.button != 3:
                return
            try:
                path, col, cellx, celly = \
                 proc_treeview.get_path_at_pos(int(event.x), int(event.y))
            except TypeError:
                return
            treeview.grab_focus()
            selection = treeview_selection

            if not selection.path_is_selected(path):
                selection.unselect_all()
                selection.select_path(path[0])

            context_menu.popup(None, None, None, event.button, event.time)
            return True

        proc_treeview.connect('button_press_event', treeview_button_press)
        dlg.connect('close', close)
        dlg.connect('response', response)
        gobject.idle_add(refresh)
        dlg.show_all()
    
    def handleVnc(self, server, port, protocol, cbStatus, viewonly=False, password=''):
        """
        Handle setting up VNC connection to port on server.
        cbStatus is called back with status messages, and finally an
        empty string when the VNC client is started.
        """
        cbStatus(_('Opening port forwarding...'))
        localPort = server.openLocalForward(0, port)
        
        vncArgv = ['xtightvncviewer', 'localhost::%d' % localPort,
                '-encodings', 'tight zrle copyrect']
        rdpArgv = ['rdesktop', 'localhost:%d' % localPort]
        if viewonly:
            vncArgv.append('-viewonly')
        if password:
            vncArgv.append('-autopass') # pass password on stdin
        if protocol == 'vnc':
            p = subprocess.Popen(vncArgv, shell=False, stdin=subprocess.PIPE)
            if password:
                p.stdin.write(password)
                p.stdin.close()
        elif protocol == 'rdp':
            p = subprocess.Popen(rdpArgv, shell=False, stdin=subprocess.PIPE)
        else:
            cbStatus(_('unknown protocol %s' % protocol))
            return
        gobject.child_watch_add(p.pid, lambda pid, condition: None) # avoid defunct process
        cbStatus(_('%s client started.') % protocol.upper())
        cbStatus('')
    
    def login(self, widget=None):
        """
        Send login request to server.
        The server returns a VNC port number one can connect to to get a login
        screen.
        """
        n, selected = self.get_selected_machines()
        if n != 1:
            return
        
        dialog = gtk.Dialog(_('Login'), None, gtk.DIALOG_DESTROY_WITH_PARENT, (gtk.STOCK_CLOSE, gtk.RESPONSE_REJECT))
        status_label = gtk.Label(_('Sending request...'))
        dialog.vbox.pack_start(status_label)
        dialog.show_all()
        dialog.connect('response', lambda *args: dialog.destroy())
        def cbStatus(status):
            if not status: # VNC client started
                dialog.destroy()
            else:
                status_label.set_text(status)
        def cbLogin(server, data, error=''):
            self.handleVnc(server, data[0]['port'],
                           data[0].get('protocol', 'vnc'), cbStatus, False, '')
            
        for server, machines in selected.iteritems():
            for userver in machines:
                server.sendRequest('login', [{'server': userver}], cbLogin)
        
    def _shutdown(self, action):
        """
        Send shutdown request to server.
        Called with action==0 for poweroff and action==1 for reboot.
        """
        n, selected = self.get_selected_machines()
        
        dlg = gtk.Dialog(_('Shutdown/reboot'), None, gtk.DIALOG_DESTROY_WITH_PARENT,
                         (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                          gtk.STOCK_OK, gtk.RESPONSE_ACCEPT))
        if action == 0:
            msg = ngettext(
                'Shutdown %(n_machines)d machine?',
                'Shutdown %(n_machines)d machines?', n) % {'n_machines': n}
        else:
            msg = ngettext(
                'Reboot %(n_machines)d machine?',
                'Reboot %(n_machines)d machines?', n) % {'n_machines': n}
        dlg.vbox.pack_start(gtk.Label(msg))
        
        def sendrequest():
            if action == 0:
                sepAction = 'poweroff'
            else:
                sepAction = 'reboot'
            
            def cbIgnore(server, data, error=''):
                pass
            
            for server, machines in selected.iteritems():
                args = [{'server': userver, 'action': sepAction }
                        for userver in machines]
                server.sendRequest('shutdown', args, cbIgnore)
        
        def close(dialog, data=None):
            dialog.destroy()
        def response(dialog, response_id, data=None):
            if response_id == gtk.RESPONSE_ACCEPT:
                gobject.idle_add(sendrequest)
            dialog.destroy()
            
        dlg.connect('close', close)
        dlg.connect('response', response)
        dlg.show_all()  
        
    def shutdown(self, widget=None):
        self._shutdown(0)
    
    def reboot(self, widget=None):
        self._shutdown(1)
        
def run():
    GtkClient(sys.argv[1:])

if __name__ == '__main__':
    run()
