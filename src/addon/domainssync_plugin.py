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


__author__="Michael Neradkov <neradkov@fastvps.ru;dev@fastvps.ru>"
__date__ ="$Dec, 2010 2:22:53 AM$"
__version__="0.5"
ISP_DIR = '/usr/local/ispmgr'

#from sys import argv
from sys import exit,path,stderr
from cgi import FieldStorage
import string

path.append(ISP_DIR + '/lib/python')
from domainssync import DomainsSyncManager, args_to_params


def func_domainssync(ds, params):
    
    if params.has_key('sok'):
        ds.log.Info('save config')
        ds.config_save(params)
        
        text = ds.config_to_xml()
        ds.log.Info('Config :' + text)

        ds.config_load()
        error = ds.get_config_error()
        if error:
            error['code'] = 8 # @todo ugly hack
            replace = '<error code="%d">%s</error><host>' % (
                                        int(error['code']), error['msg'])
            text = string.replace(text, '<host>', replace)
        else:
            text ='<?xml version="1.0" encoding="UTF-8"?><doc><ok/></doc>'
            
    else: 
        ds.log.Info('edit config')
        text = ds.config_to_xml()
    return text


def func_domainssync_edit(ds):
    ds.log.Info('config_edit')
    return '<?xml version="1.0" encoding="UTF-8"?><doc><elid/></doc>' 

def func_domainssync_save(ds):
    ds.log.Info('config_save')
    return ds.get_empty_result()


#==============================================================================
if __name__ == "__main__":
    ds = DomainsSyncManager()
    try:
        args = FieldStorage(keep_blank_values=True)
        
        params = args_to_params(args)
        
        ds.log.Debug('Params [%s]' % params)
        if params.has_key('out'):
            if params['out'] == 'text':
                print 'Text'
                exit(0)
                
        if params['func'] == 'domainssync':
            text = func_domainssync(ds, params)
        elif params['func'] == 'domainssync.edit':
            text = func_domainssync_edit(ds)
        elif params['func'] == 'domainssync.save':
            text = func_domainssync_save(ds)
                
        print text
                
    except Exception, ex:
        import traceback
        ds.get_error_exit('Unable to sync [%s] [%s]' % 
                          (ex, traceback.format_exc()))

    exit(0)
        
        
