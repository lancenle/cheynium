#!/usr/bin/env python

# Python tested is 3.8.5, ensure /usr/bin/python exist
# Postgres 


from datetime import datetime
import json
import optparse
import os
import paramiko         #ssh
import urllib.request   #http/https check



#Standard and debug logs go to gsFileLog
gsFileLog   = '../logs/cheynium.log'
gsFileError = '../logs/cheynium-error.log'
gbDebug     = False



#from ConfigParser import SafeConfigParser;

#strConfig = json.loads('/home/default/cheynium/configs/cheynium.ini')
#print (data["formatjson"]);



def LogDebug(strEntry):
   try: 
      if gbDebug == True:
         print(strEntry)

         with open(gsFileLog, 'a+') as fileLog:
            fileLog.write(strEntry + '\n')
            fileLog.close() 
   except:
      print('Writing debug info to ' + gsFileLog + ' exception')



def LogEntry(strEntry):
   try: 
      if gbDebug == True:
         print(strEntry)

      with open(gsFileLog, 'a+') as fileLog:
         fileLog.write(strEntry + '\n')
         fileLog.close() 
   except:
      print('Writing to log file ' + gsFileLog + ' exception')



def LogError(strEntry):
   try: 
      if gbDebug == True:
         print(strEntry)

      with open(gsFileError, 'a+') as fileError:
         fileError.write(strEntry + '\n')
         fileError.close() 
   except:
      print('Writing to error file ' + gsFileError + ' exception')




# If http/https monitor, get the json structure
# Hit the URL, and check the response to see if it matches the expected response
# Currently, port and timeout are not used.
def ProcessHTTPMonitor(jsonMonitorData):
   sUrl              = str(jsonMonitorData['url'])
   nPort             = jsonMonitorData['port']
   nInterval         = jsonMonitorData['interval']
   sTimeUnit         = str(jsonMonitorData['timeunit'])
   sExpectedResponse = str(jsonMonitorData['response'])

   
   LogEntry('Checking URL ' + sUrl)
   
   try:
      structResponse = urllib.request.urlopen(sUrl)
   except URLError:
      print('Got a URLError')

   if str(structResponse.getcode()) == sExpectedResponse:
      LogEntry('Success got response ' + sExpectedResponse)
   else:
      LogEntry(sUrl + ' not reachable ')


   sDirSQL = '/home/default/cheynium/sql'
   for filename in os.scandir(sDirSQL):
      if filename.path.endswith(".sql") and filename.is_file():
         sDirFile = os.path.join(sDirSQL,filename)
         LogEntry('Reading monitor ' + sDirFile)


   # Return the response to determine where to write the results
   return(structResponse)




# If SSH monitor, get the json structure
# Log into destination via SSH and check disk free
# Currently, port and timeout are not used.
def ProcessSSHDiskUsageMonitor(jsonMonitorData):
   sHostname         = str(jsonMonitorData['hostname'])
   sFolder           = str(jsonMonitorData['folder'])
   sPrivateKey       = str(jsonMonitorData['privatekey'])
   sUser             = str(jsonMonitorData['user'])
   nInterval         = jsonMonitorData['interval']
   sTimeUnit         = str(jsonMonitorData['timeunit'])

   
   LogEntry('Checking SSH disk usage for ' + sHostname + ':' + sFolder)

   sCommand = "df " + sFolder + "| awk '{print $5}' | grep -v -i use"

   LogDebug(sCommand)

   try:
      # Private key should be in PEM format
      # ssh-keygen -m pem -t rsa -b 2048 -f /tmp/newkey
      sRSAKey = paramiko.RSAKey.from_private_key_file(sPrivateKey)

      client = paramiko.SSHClient()
      client.load_system_host_keys()
      client.set_missing_host_key_policy(paramiko.WarningPolicy)
      #client.set_missing_host_key_policy(paramiko.AutoAddPolicy())


      #client.connect(hostname=sHostname, key_filename=sPrivateKey, username=sUser, password = '')
      client.connect(hostname=sHostname, pkey=sRSAKey, username=sUser)

      stdin, stdout, stderr = client.exec_command(sCommand)

      #The return string is b', and we need to decode it into a string
      #Strip the newline character
      sResult = stdout.read().decode()
      sResult = sResult.replace('\n', '')

      LogEntry('Folder ' + sFolder + " is "+ sResult + " full")
#      print(stderr.read())

   except AuthenticationException:
      LogError("Authentication failed, please verify your credentials: %s")
      LogError("Key pair may not be correct or user may not exist")
      LogError("Key format may not be in pem format")
   except SSHException as sshException:
      LogError("Unable to establish SSH connection: %s" % sshException)
   except BadHostKeyException as badHostKeyException:
      LogError("Unable to verify server's host key: %s" % badHostKeyException)
   finally:
      client.close()

   # Return the response to determine where to write the results
   return(sResult)




# Main entry point.
# loop through directory containing monitor configurations specified in the ini file
# the monitor configuration directory is specified in the main .ini file

# Parse command line for flags
# --version
# --debug
# --ini
parser = optparse.OptionParser(usage='usage: %prog [options]', version='%prog 1.0.0')
parser.add_option("--debug",
                  action='store_true',
                  default=False,
                  help='Enable debugging by printing logs to standard output')

parser.add_option("--initfile",
                  dest="initfilename",
                  metavar="FILE",
                  default='/home/default/cheynium/configs/cheynium.ini',
                  help='Initial configuration file')

(options,args)=parser.parse_args()






# When debugging is enable, entries to log file is also printed to stdout
# Debugging also prints additional entries to stdout
if options.debug == True:
   print('Debugging enabled')
   gbDebug = True


# Open the init configuration from command line, if not specified, then open
# default init file in configs directory
if not options.initfilename:
   sInitFile = options.default
else:
   sInitFile = options.initfilename



with open(sInitFile, 'r') as fileInit:
   initdata = fileInit.read()
   initobj  = json.loads(initdata)

   gsFileLog         = str(initobj['filelog'])
   gsFileError       = str(initobj['fileerror'])

   sDirMonitors      = str(initobj['dirmonitor'])
   sDirMonitorOutput = str(initobj['dirmonitoroutput'])
   bWriteOutputfile  = initobj['writetooutputfile']

   fileInit.close()



# Start by writing datestamp to log file
LogEntry('\n\nStarting at ' + datetime.now().strftime("%d/%m/%Y %H:%M:%S")) #Log starting time



for filename in os.scandir(sDirMonitors):
  if filename.path.endswith(".mon") and filename.is_file():
     sDirFile = os.path.join(sDirMonitors,filename.name)
     LogEntry('Reading monitor ' + sDirFile)


     with open(sDirFile, 'r') as myfile:
        data = myfile.read()
        obj  = json.loads(data)

        sMonitorType = str(obj['monitortype'])

        myfile.close() 


        # SSH monitors can have many subtypes (module), like disk free check
        # A key pair is needed, to create ssh-keygen -t rsa -b 2048 -f /tmp/newkey
        # The public portion will need to be placed on destination
        # The private key will need to be placed in the keys folder
        if sMonitorType.lower() == 'ssh':
           sMonitorSubType = str(obj['module'])

           if sMonitorSubType == 'diskusage':
              LogEntry('Processing SSH disk usage monitor')
              structResponse = ProcessSSHDiskUsageMonitor(obj)

           elif sMonitorSubType == 'disksize':
              LogEntry('Disk size check in development')
 


        if sMonitorType.lower() == 'http' or sMonitorType.lower() == 'https':
           LogEntry('Processing HTTP monitor')
           structResponse = ProcessHTTPMonitor(obj)
    
           if str(structResponse.getcode()) == str(obj['response']):
              LogEntry('Write something good')
           else:
              LogEntry('Write something bad')

        
    

# if tcp
# if api
# if string found on url
# if port check
# if ssh
#   //ssh module can log into the server and run some commands
#   //disk size
#   //network usage
#   //connections
#   //bandwidth
#   //services


# Write condition of monitor to database
# write results to output file, database, or both
# read the configuration file to determine where output is to be written
# if output is to database, the sql statement should match
# e.g. http monitor shoud have a matching http-sql

