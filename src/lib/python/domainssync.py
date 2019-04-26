#!/usr/bin/env python
# -*- coding: utf-8 -*-
ISP_DIR = '/usr/local/ispmgr'

import requests
import json
import time
from sys import exit,path,stderr
from xml.dom import minidom
import os
import time
import ConfigParser
from xml.dom import minidom


BASEURL = "https://fastdns.fv.ee"
ISP_LOG = ISP_DIR + '/var/ispmgr.log'
path.append(ISP_DIR + '/lib/python')


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

def get_elid(name):
    if name[-1] == '.':
        elid = name[:-1]
    else:
        elid = name
    return elid

def get_name(name):
    if name[-1] != '.':
        name = name + '.'

    return name

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

class DomainsSyncManager:
    token = ""
    log = None
    name = 'domainssync'
    fastdns = {}
    authToken = ""
    config      = None
    config_file = None

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
                default_params = {'host': BASEURL,
                           'token' : 'xxx'}
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
           # self.config.readfp(open(self.config_file))
            self.config.read(self.config_file)
        except Exception, ex:
            msg = 'Unable to read config file [%s]' % self.config_file
            self.log.Error(msg)
            #raise Exception(msg)
        try:
            self.log.Debug('Try to parse config')
            self.log.Debug("%s" % self.config)
            self.fastdns['token'] = self.config.get('fastdns', 'token')
            self.authToken = self.fastdns['token']
        except Exception, ex:
            self.log.Error(ex)
            msg = 'Unable to parse config file [%s]' % self.config_file
            self.log.Error(msg)
            #raise Exception(msg)

        try:
            self.log.__llevel = self.config.getint('log', 'level')
            msg = 'Get LogLevel from ISPManager [%s]' % (self.log.__llevel, )
        except Exception, ex:
            self.log.__llevel = 1
            msg = 'Unable to get LogLevel from ISPManager [%s] - using default [1]'

        self.log.Debug(msg)

    def get_domain_id(self, name):
        name = unicode(name, "utf-8")
        name = name.encode('idna')
        self.log.Info("Try to find '%s domain" % name)
        try:
            r = self.send_fastdns_request('GET', "/api/domains/%s/name" % name, {})
            respData = json.loads(r.text)
            return respData['id']
        except Exception as e:
            self.log.Error('Domain [%s] not found' % name)
            raise e

    def send_domain_create_request(self, params):
        self.log.Debug("Given create domain params %s" % params)
        self.log.Info("Try to create '%s domain" % params['name'])
        # do not create www and mail domains at parent DNS
        if 'webdomain' in params:
            del params['webdomain']
        if 'maildomain' in params:
            del params['maildomain']
        # create domain
        requestData = {
           'name': params['name'],
           'ip': params['ip'],
           'mail_service': 0
        }

        try:
            r = self.send_fastdns_request('POST', "/api/domains", requestData)
            respData = json.loads(r.text)
            self.log.Info('Domain [%s] was created remotely' %
                 (params['name']))
            self.log.Debug('Creating subdomains for [%s] at [%s]' % (params['name'], params['ip']))
            self.create_predefined_subdomains(respData['id'], params['name'], params['ip'])
        except Exception as e:
            msg = 'Domain [%s] was NOT created - Error [%s]' % (params['name'], e)
            self.log.Error(msg)
            raise Exception(e)

        return


    def create_predefined_subdomains(self, domainId, parent_domain, ip):
        ''' Create a set of predefined subdomains for parent domain'''
        subdomains_set = ('ftp', 'pop', 'smtp') #'mail',
        for name in subdomains_set:
            # create domain
            requestData = {
               'name': name + "." + get_name(parent_domain),
               'content': ip,
               'type': 'A'
            }
            self.send_fastdns_request('POST', "/api/domains/%s/records" % domainId, requestData)

    def delete_domain(self, params):
        try:
            dID = self.get_domain_id(params['elid'])
            self.send_fastdns_request('DELETE', "/api/domains/%s" % dID, {})
        except Exception as e:
            msg = "Domain [%s] not found" % params['elid']
            self.log.Error(msg)
            raise Exception(msg)


    def get_record_id(self, dID, domainName, elid, rType):
        try:
            nElid = self.add_origin_to_elid(elid, domainName, rType)
            self.log.Info("try to find '%s' record" % nElid)
            uri = str("/api/domains/%d/records/%s/elid" % (dID, nElid))
            r = self.send_fastdns_request('GET', uri, {})
            respData = json.loads(r.text)
            return respData['id']
        except:
            self.log.Error("record '%s' not found in '%s' zone" % (nElid, domainName))
            raise Exception("Record '%s' not found remotely" % elid)

    def add_origin_to_elid(self, elid, origin, sdtype):
        origin = unicode(origin, "utf-8")
        origin = origin.encode('idna')
        fields = elid.split()
        fields[0] = self.add_origin(fields[0], origin)
        if sdtype == 'CNAME':
            if not self.isFqdn(fields[2]):
                fields[2] = self.add_origin(fields[2], origin)
        if sdtype == 'SRV':
            if not self.isFqdn(fields[len(fields)-1]):
                fields[len(fields)-1] = self.add_origin(fields[len(fields)-1], origin)
        if sdtype == 'MX':
            if not self.isFqdn(fields[3]):
                fields[3] = self.add_origin(fields[3], origin)

        self.log.Info("field %s" % fields)
        return " ".join(fields)

    def add_origin(self, name, origin):
        self.log.Info("origin %s" % origin)
        if self.isFqdn(name):
            return name

        if len(origin) == 0:
            return name

        if name == '@' or len(name) == 0:
            return self.fqdn(origin)

        if origin == '.':
            return self.fqdn(name)

        return name + "." + self.fqdn(origin)

    def isFqdn(self, name):
        return (name[-1] == '.')

    def fqdn(self, name):
        if name[-1] != '.':
            name = name + '.'

        return name

    def add_record(self, params):
        self.log.Debug("Given add record params %s" % params)
        dID = self.get_domain_id(params['plid'])
        requestData = {
           'name': self.add_origin(params['name'], params['plid']),
           'content': params['addr'],
           'type': params['sdtype'],
        }
        if params.has_key('prio') and params['prio'] != "":
            requestData['priority'] = int(params['prio'])
        if params.has_key('wght') and params['wght'] != "":
            requestData['weight'] =  int(params['wght'])
        if params.has_key('port') and params['port'] != "":
            requestData['port'] = int(params['port'])

        self.send_fastdns_request('POST', "/api/domains/%s/records" % dID, requestData)

    def elid_to_params(self, elid):
        fields = elid.split()
        params = {
            'name': fields[0],
            'sdtype': fields[1],
            'addr': fields[2],
        }

        return params

    def update_record(self, params):
        self.log.Debug("Given updates params %s" % params)
        rParams = self.elid_to_params(params['elid'])
        if rParams['sdtype'] != params['sdtype']:
            raise Exception("Record type can not be changed")

        dID = self.get_domain_id(params['plid'])
        rId = self.get_record_id(dID, params['plid'], params['elid'], rParams['sdtype'])
        requestData = {
           'name': self.add_origin(params['name'], params['plid']),
           'content': params['addr'],
           'type': params['sdtype'],
        }
        if params.has_key('prio') and params['prio'] != "":
            requestData['priority'] = int(params['prio'])
        if params.has_key('wght') and params['wght'] != "":
            requestData['weight'] =  int(params['wght'])
        if params.has_key('port') and params['port'] != "":
            requestData['port'] = int(params['port'])

        uri =  "/api/domains/%s/records/%s" % (dID, rId)
        self.send_fastdns_request('PUT', uri, requestData)
        self.log.Info("Record '%s' successfully updated" % params['elid'])

    def delete_record(self, params):
        self.log.Debug("Given delete params %s" % params)
        self.log.Info("try to delete '%s' record from '%s' zone" % (params['elid'], params['plid']))
        dID = self.get_domain_id(params['plid'])

        rParams = self.elid_to_params(params['elid'])
        rId = self.get_record_id(dID, params['plid'], params['elid'], rParams['sdtype'])
        uri =  "/api/domains/%s/records/%s" % (dID, rId)
        self.send_fastdns_request('DELETE', uri, {})
        self.log.Info("Record '%s' deleted successfully" % params['elid'])

    def send_fastdns_request(self, method, uri, params):
        url = BASEURL + uri
        headers = {
            'Authorization': 'Bearer ' + self.token,
            "Content-Type": "application/json",
            "language": "en"
        }
        data = json.dumps(params)
        self.log.Info("send %s" % data)
        self.log.Info("uri %s" % uri)
        r = {}
        if method == 'GET':
            r = requests.get(url, headers=headers, verify=False)
        if method == 'POST':
            self.log.Info(method)
            r = requests.post(url, data=data, headers=headers, verify=False)
        if method == 'PUT':
            r = requests.put(url, data=data, headers=headers, verify=False)
        if method == 'DELETE':
            r = requests.delete(url, headers=headers, verify=False)
        if r.status_code == 404:
            raise Exception("Resource not found")
        if r.status_code >= 400 and r.status_code <= 511:
            rData = json.loads(r.text)
            self.log.Info("%s" % rData)
            raise Exception(self.get_error(rData))
        return r

    def get_error(self, jsonReponse):
        msg = "something gone wrong"
        if 'errors' in jsonReponse:
            errors = jsonReponse['errors']
            for key in errors:
                msg = "{}".format(str(errors[key]))
        return msg

     #    return text
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

    def auth(self):
        headers = {'Authenticate': self.authToken}
        url = BASEURL + '/login_token'
        r = requests.post(url, headers=headers, verify=False)
        if r.status_code == 200:
            json_data = json.loads(r.text)
            self.log.Info("%s" % json_data)
            self.token = json_data['token']
            return
        raise Exception('Bad credentials')

    def send_isp_request(self, params, type='xml', out='doc'):
        '''Get XML result of isp request'''
        try:
            self.auth()
        except Exception as e:
            self.log.Debug('Get FASTDNS response in [%s]' % (e))
            raise Exception(e)

    def config_to_xml(self):
        """Get config for interface edit"""
        tpl = """<?xml version="1.0" encoding="UTF-8"?><doc><elid/>
        <token>%s</token>
        </doc>"""
        return tpl % self.fastdns['token']

    def get_config_error(self):
        params = {'func' : 'domain'}
        self.send_isp_request(params)
        return

    def config_save(self, params):
        """Save config file"""
        cfg_tpl = """

[fastdns]
token = %s

[log]
; 9 - Debug
; 6 - Note
; 5 - Extend info
; 4 - Info
; 2 - Warning
; 1 - Error
level = %s
"""
        self.log.Info("save %s" % self.config_file)
        args = (params['token'], self.log.__llevel)
        cfg = cfg_tpl % args

        fp = open(self.config_file, "w")
        fp.write(cfg)
        fp.close()
        os.chmod(self.config_file, int("0600", 16))
