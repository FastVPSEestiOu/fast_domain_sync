#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Domain's Sync - plugin for sync domains between 2 instance of ISP Manager

Copyright (C) 2011  Michael Neradkov <neradkov@fastvps.ru;dev@fastvps.ru> 
FastVPS LLC
 194044 Saint-Petersburg, B. Sampsonievsky, 60, lit.A

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''


ISP_DIR = '/usr/local/ispmgr'

from sys import exit,path,stderr
from xml.dom import minidom
import os
import time
import urllib
import ConfigParser

path.append(ISP_DIR + '/lib/python')
import mgr

ISP_LOG = ISP_DIR + '/var/ispmgr.log'
#ISPMGR_CONFIG_PATH = ISP_DIR + '/etc/ispmgr.conf'
REMOTE_ISP_URL = 'https://ns3.fastvps.ru'
# Таймаут для запроса к NS3
ISP_REQUEST_TIMEOUT = 90

os.chdir(ISP_DIR)


#==============================================================================
def isp_local_request(func, params, out=None):
    from subprocess import Popen, PIPE
    #keys_str = ' '.join(["=".join(map(str,k)) for k in keys])
    
    str = ''
    for key, value in params.iteritems():
        str = str + key + '=\'' + value + '\' '
        
    q = """%s %s""" % (func, str[:-1])
    print q
    if out is not None:
        type = 'xml'
    else:
        type = 'text'
    cmd = '/usr/local/ispmgr/sbin/mgrctl -m ispmgr -o %s %s' % (type, q)
    
    print "\n\033[0m"+cmd
    res = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE).communicate()[0]
    
    return res

#==============================================================================
def args_to_params(args):
    keys = args.keys()
    params = {}
    
    for key in keys:
        try:
            value = args[key].value
            params[key] = value
            
        except:
            pass
    
    return params

#==============================================================================
def get_elid(name):
    if name[-1] == '.':
        elid = name[:-1]
    else:
        elid = name
    return elid

#==============================================================================
def get_name(name):
    if name[-1] != '.':
        name = name + '.'

    return name


#==============================================================================
class Log:
    """Logging class"""
    __fname = 0
    __llevel = 1
    __pname = ''
    __colors = ["\033[0m",
            "\033[1;31mFATAL",
            "\033[1;35mWARNING",
            "\033[1;33mDEBUG",
            "\033[1;32mINFO",
            "\033[1;36mEXTINFO",
            "\033[1;34mNOTE"]

    #--------------------------------------------------------------------------
    def __init__(self, pname='ispplugin', logname=ISP_LOG, loglevel=9):
        self.__fname = open(logname, 'a')
        self.__llevel = loglevel
        self.__pname = pname

    #--------------------------------------------------------------------------
    def ustr(self, string):
        """Convert any string to <str> type"""
        if type(string).__name__ == 'unicode':
            value = string.encode('utf-8')
        else:
            value = string
        return value

    #--------------------------------------------------------------------------
    def __write(self, msg='', colortype=0):
        """Writing data to file"""
        self.__fname.write("%s %s %s %s %s\n" %\
                (self.ustr(time.strftime('%b %d %H:%M:%S')),
                self.__pname,
                self.__colors[colortype],
                self.ustr(msg),
                self.__colors[0]))

    #--------------------------------------------------------------------------
    def Warn(self, msg):
        """Warning log leve;"""
        if self.__llevel >= 2:
            self.__write(msg, 2)

    #--------------------------------------------------------------------------
    def Debug(self, msg):
        """Debug log level"""
        if self.__llevel >= 9:
            self.__write(msg, 3)

    #--------------------------------------------------------------------------
    def Error(self, msg):
        """Error log level"""
        self.__write(msg, 1)

    #--------------------------------------------------------------------------
    def Info(self, msg):
        """Info log level"""
        if self.__llevel >= 4:
            self.__write(msg, 4)

    #--------------------------------------------------------------------------
    def ExtInfo(self, msg):
        """ExtInfo log level"""
        if self.__llevel >= 5:
            self.__write(msg, 5)

    #--------------------------------------------------------------------------
    def Note(self, msg):
        """ExtInfo log level"""
        if self.__llevel >= 6:
            self.__write(msg, 6)
        
        
        
#==============================================================================
class DomainsSyncManager:
    name = 'domainssync'
    config      = None
    config_file = None
    log = None
    isp = {}
    
    #--------------------------------------------------------------------------
    def __init__(self):
        '''
        Read and parse config files
        '''
        self.log = Log(self.__class__.__name__)
        self.log.__llevel = 9
        
        # @todo tolower
        self.config_file = ISP_DIR+'/etc/'+self.name+'.ini'
        
        if not os.path.exists(self.config_file):
            try: 
                default_params = {'host': REMOTE_ISP_URL, 
                           'username' : 'xxx',
                           'password' : 'xxx' }
                self.config_save(default_params)
            except Exception, ex:
                msg = 'Unable to save config file [%s] - Error: [%s]' % (self.config_file, ex)
                self.log.Error(msg)
                raise Exception(msg)
        
        
        stderr = self.log
        self.config_load()
        
    #--------------------------------------------------------------------------
    def config_load(self):
        ''' Load config files '''

        try:
            self.config = ConfigParser.ConfigParser()
            self.log.Debug('Try to read config [%s]' % (self.config_file, ))
            self.config.readfp(open(self.config_file))
        except Exception, ex:
            msg = 'Unable to read config file [%s]' % self.config_file
            self.log.Error(msg)
            #raise Exception(msg)

        try:
            self.log.Debug('Try to parse config')
            #self.log.__llevel = int(self.config.get('log', 'level'))
            self.isp['host'] = self.config.get('isp_master', 'host') 
            self.isp['username'] = self.config.get('isp_master', 'username')
            self.isp['password'] = self.config.get('isp_master', 'password')
            #self.config.read([file1, file2])
        except Exception, ex:
            msg = 'Unable to parse config file [%s]' % self.config_file
            self.log.Error(msg)
            #raise Exception(msg)
        
        
        try:
            #ret = isp_local_request('paramlist', {'elid' : 'LogLevel'})
            #data = ret.split('=')
            #self.log.__llevel = int(data[1])
            self.log.__llevel = self.config.getint('log', 'level')
            msg = 'Get LogLevel from ISPManager [%s]' % (self.log.__llevel, )
        except Exception, ex:
            self.log.__llevel = 1
            msg = 'Unable to get LogLevel from ISPManager [%s] - using default [1]'
        
        self.log.Debug(msg)
        

    #--------------------------------------------------------------------------
    def send_isp_request(self, params, type='xml', out='doc'):
        '''Get XML result of isp request'''
        print "Content-type: text/html\n\n"
        
        default_params = {
            'authinfo' : self.isp['username']+':'+self.isp['password'],
            # @todo type
            'out' : 'xml'
        }
    
        url_params = default_params
        keys = params.keys()
        
        for key, value in params.iteritems():
            url_params[key] = value
        
       
        url = self.isp['host']+'/manager/ispmgr?'+urllib.urlencode( url_params )
        self.log.ExtInfo('Send ISP request [%s]' % (url, ))
        # res =    urllib.urlopen(url, {}, ISP_REQUEST_TIMEOUT)
        import urllib2
        import socket
        socket.setdefaulttimeout(ISP_REQUEST_TIMEOUT)
        
        try:
            res = urllib2.urlopen(url)
            if type == 'xml':
                xmldoc = minidom.parse(res)
                text = xmldoc.toxml("UTF-8")
                if out == 'doc': 
                    result = xmldoc
                else:
                    result = text
            else:
                text  = res
                result = res
        except:
            msg = u'ISP Manager not found at [%s]' % (self.isp['host'], )
            if type == 'xml':
                text = u'<?xml version="1.0" encoding="UTF-8"?><doc><error code="8">%s</error></doc>' % (msg, )
                result = minidom.parseString(text)
            else:
                text = msg 
                result = text
         
            
        self.log.Debug('Get ISP response in [%s] - [%s] as [%s]' % 
                       (type, text, out))
    
        return result
    
    #--------------------------------------------------------------------------
    def create_predefined_subdomains(self, parent_domain, ip):
        ''' Create a set of predefined subdomains for parent domain'''
        subdomains_set = ('ftp', 'pop', 'smtp') #'mail',
        for name in subdomains_set:
            params = {
                'name'   : name,
                'func'   : 'domain.sublist.edit',
                'plid'   : get_elid(parent_domain),
                'addr'   : ip,
                'sok'    : 'yes',
                'sdtype' : 'A'
            }
            xmldoc = self.send_isp_request(params)
            
            try: 
                '''
                er_elements = xmldoc.getElementsByTagName('error')
                for er_el in er_elements:
                    er_msg  = er_el.childNodes[0].data
                    er_code = er_el.getAttribute('code')
                '''
                error = self._get_xml_response_error(xmldoc)
                if error:
                    raise Exception ('ISP error code [%s] with message [%s]' %
                                    (error['code'], error['msg']))
                self.log.Info('SubDomain [%s.%s] was created remotely' % 
                         (name, parent_domain))
            except Exception, ex:
                self.log.Error('SubDomain [%s.%s] was NOT created - Error [%s]' %
                          (name, parent_domain, ex))        
        return self.get_empty_result()
    
    
    #--------------------------------------------------------------------------
    def _get_xml_response_error(self, xmldoc):
        ''' Check and get error in XML document - ISP response '''
        er_elements = xmldoc.getElementsByTagName('error')
        for er_el in er_elements:
            er_msg  = er_el.childNodes[0].data
            er_code = er_el.getAttribute('code')
            return {'code' : er_code, 'msg': er_msg}
        return None
    
    #--------------------------------------------------------------------------
    def send_domain_create_request(self, params):
        
        # do not create www and mail domains at parent DNS    
        if 'webdomain' in params:
            del params['webdomain']
        if 'maildomain' in params:
            del params['maildomain']

        xmldoc = self.send_isp_request(params)
        text = xmldoc.toxml("UTF-8")
        
        try:
            errors = xmldoc.getElementsByTagName('error')
            if len(errors) == 0:
                self.log.Info('Domain [%s] was created remotely' % 
                     (params['name'],))
            else:
                raise
        except:
            self.log.Error('Domain [%s] was NOT created - Error [%s]' % 
                      (params['name'], text))
            return text
    
        func = params['func']
        elid = params['elid']
        
        # @todo New domain creating
        if (func == 'domain.edit' and not len(elid)): 
            elid     = get_name(params['name'])
            ip       = params['ip']
            isp_ip   = '78.47.76.4' # @todo
            txt_elid = ('%s TXT  v=spf1 ip4:%s a mx ~all' % (params['name'], isp_ip));
            
            new_params = {
                'elid' : params['name'],
                'func' : 'domain.sublist'
            }
            xmldoc = self.send_isp_request(new_params)
            
            # get ELID from fresh TXT record
            try:
                elements = xmldoc.getElementsByTagName('elem')
                self.log.Info('elements count [%s]' % len(elements))
                
                for elem in elements:
                    types_elements = elem.getElementsByTagName('type')
                    for type_el in types_elements:
                        type = type_el.childNodes[0].data
                        self.log.Debug('element type=[%s]' % type)
                        
                        if type == 'TXT':
                            self.log.Debug('first child type=[%s]' % '5')
                            key_elements = elem.getElementsByTagName('key')
                            for key_el in key_elements:
                                self.log.Debug('first child key=[%s]' % '6')
                                txt_elid  = key_el.childNodes[0].data
                                self.log.Info('TXT elid for fixing is [%s]' % txt_elid)
            except Exception, ex:
                self.log.Error('Unable to process XML - [%]' % ex)
                
    
            import socket
            client_ip = socket.gethostbyname(socket.gethostname())
            self.log.Debug('Fixing SPF record')
            
                
            new_params = {
                'elid'   : '', #txt_elid,
                'addr'   : ('v=spf1 ip4:%s a mx ~all' % client_ip),
                'sdtype' : 'TXT',
                'name'   : elid,
                'prio'   : '',
                'sok'    : 'yes',
                'func'   : 'domain.sublist.edit',
                'plid'   : params['name'],
                'wght'   : '',
                'port'   : ''
            }
            xmldoc = self.send_isp_request(new_params)
            
            self.log.Debug('Creating subdomains for [%s] at [%s]' % (params['name'], ip))
            reply = self.create_predefined_subdomains(params['name'], ip)
        
        return text
    
    #--------------------------------------------------------------------------
    def send_domain_edit_request(self, params):

        xmldoc = self.send_isp_request(params)
        text = xmldoc.toxml("UTF-8")
        
        try:
            errors = xmldoc.getElementsByTagName('error')
            if len(errors) == 0:
                self.log.Info('Domain [%s] was updated remotely' % 
                     (params['elid'],))
                return self.get_empty_result()
                #return text
            else:
                raise
        except Exception, ex:
            self.log.Error('Domain [%s] was NOT updated - Error [%s] [%s]' % 
                      (params['elid'], text, ex))

        return text        
            
    
    #--------------------------------------------------------------------------
    def get_empty_result(self):
        xmldoc = minidom.Document()
        doc = xmldoc.createElement('doc')
        xmldoc.appendChild(doc)
        return xmldoc.toxml("UTF-8")

        
    #--------------------------------------------------------------------------
    def get_error_exit(self, string, errcode=0):
        """Print xml with error and exit"""
        xmldoc = minidom.Document()
        doc = xmldoc.createElement('doc')
        xmldoc.appendChild(doc)
        
    #    string = re.sub('\'', '"', string)
        if type(string).__name__ == 'str':
            errstring = string.decode('utf-8')
        else:
            errstring = string
    
        erel = xmldoc.createElement('error')
        doc.appendChild(erel)
    
        ertxt = xmldoc.createTextNode(errstring)
        erel.appendChild(ertxt)
    
        if errcode > 0:
            erel.setAttribute('code', str(errcode))
        
        #if errcode > 0:
        #    erel.setAttribute('obj', '')
    
        txt = xmldoc.toxml("UTF-8")
        
        self.log.Error(txt)
    
        print txt
        exit(0)
        
    
    #--------------------------------------------------------------------------
    def config_save(self, params):
        """Save config file"""
        cfg_tpl = """
[isp_master]
host = %s
username = %s
password = %s

[log]
; 9 - Debug
; 6 - Note
; 5 - Extend info
; 4 - Info
; 2 - Warning
; 1 - Error

level = %s
"""
        
        args = (params['host'], params['username'], 
                params['password'], self.log.__llevel)
        cfg = cfg_tpl % args
        
        fp = open(self.config_file, "w")
        fp.write(cfg)
        fp.close()
        os.chmod(self.config_file, int("0600", 16))
    
    #--------------------------------------------------------------------------
    def get_config_error(self):
        params = {'func' : 'domain'}
        xmldoc = self.send_isp_request(params)
        error = self._get_xml_response_error(xmldoc)
        return error 
        
    #--------------------------------------------------------------------------
    def config_to_xml(self):
        """Get config for interface edit"""
        tpl = """<?xml version="1.0" encoding="UTF-8"?><doc><elid/>
        <host>%s</host>
        <username>%s</username>
        <password>%s</password>
        </doc>"""
        args = ( self.isp['host'], 
                self.isp['username'], self.isp['password'])

        return tpl % args
        
