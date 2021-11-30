import time
from pprint import pprint
from zapv2 import ZAPv2
import argparse
import os
import sys
from yaml import load
import subprocess
import platform

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper
from datetime import datetime
from threading import Thread

#######################################
###           ARGPARSE              ###
#######################################

parser = argparse.ArgumentParser(description='Zap proxy client script')
parser.add_argument('--use-env', default=False, help='Read configurations from env', action='store_true')
parser.add_argument('--zap-host', type=str, default='localhost', help='Zap host to connect to', action='store')
parser.add_argument('--zap-port', type=int, default='5555', help='Zap port to connect to', action='store')
parser.add_argument('--zap-home', type=str, help='Zap home path for current project')
parser.add_argument('--scripts-path', type=str, help='Path of the scripts to load')
parser.add_argument('--session-name', type=str, help='Session name')
parser.add_argument('--context-name', type=str, help='Conext name')
parser.add_argument('--include-urls', type=str, help='Urls to include: url1,url2,...')
parser.add_argument('--exclude-urls', type=str, default=None, help='Urls to exclude: url1,url2,...')
parser.add_argument('--report-name', type=str, help='Name of the report')
parser.add_argument('--starting-point', type=str, help='Starting point url')
parser.add_argument('--auth', default=None, help='Use authentication: scriptBasedAuthentication, basicAuthentication.')
parser.add_argument('--username', default='', type=str, help='Auth Username')
parser.add_argument('--password', default='', type=str, help='Auth Password')
parser.add_argument('--use-ajax-spider', default=False, action='store_true', help='Use ajax Spider')
parser.add_argument('--additional-urls', type=str, help='Additional urls to help zap scan')
parser.add_argument('--ajax-timeout', type=str, default='5', help='Ajax spider scan timeout')

args = parser.parse_args()

# GET ENVIRONMENT GENERAL CONFIG VARIABLE
zap_proxy_home = os.environ.get('ZAPROXY_HOME')
build_id = os.environ.get('BUILD_ID')
workspace = os.environ.get('WORKSPACE')

#######################################
###         END OF ARGPARSE         ###
#######################################


#######################################
###           VARIABLES             ###
#######################################

apiKey = 'zapapisecret'
zapStarted = False

zap_host = os.environ.get('ZAP_HOST') if args.use_env else args.zap_host
zap_port = os.environ.get('ZAP_PORT') if args.use_env else args.zap_port
zap_home = os.environ.get('ZAP_HOME') if args.use_env else args.zap_home
scripts_path = os.environ.get('SCRIPTS_PATH') if args.use_env else args.scripts_path
session_name = os.environ.get('SESSION_NAME') if args.use_env else args.session_name
context_name = os.environ.get('CONTEXT_NAME') if args.use_env else args.context_name
include_urls = os.environ.get('INCLUDE_URLS') if args.use_env else args.include_urls  # Urls format url1,url2,url3
exclude_urls = os.environ.get('EXCLUDE_URLS') if args.use_env else args.exclude_urls  # Urls format url1,url2,url3
starting_point = os.environ.get('STARTING_POINT') if args.use_env else args.starting_point
report_name = os.environ.get('REPORT_NAME') if args.use_env else args.report_name
authMethod = os.environ.get('AUTH') if args.use_env else args.auth
username = os.environ.get('USERNAME') if args.use_env else args.username
password = os.environ.get('PASSWORD') if args.use_env else args.password
# MANDATORY. Set True to use Ajax Spider, False otherwise.
useAjaxSpider = os.environ.get('USE_AJAX_SPIDER', 'False').lower() in (
    'true', '1', 't') if args.use_env else args.use_ajax_spider
ajax_timeout = os.environ.get('AJAX_TIMEOUT', 5) if args.use_env else args.ajax_timeout
additional_urls = os.environ.get('ADDITIONAL_URLS',
                                 []) if args.use_env else args.additional_urls  # Urls format url1,url2,url3

# Print all configurations
print('ENV CONFIGURATIONS:'
      '\n\tZAP_PROXY_HOME={}'
      '\n\tBUILD_ID={}'
      '\n\tZAP_HOST={}'
      '\n\tZAP_PORT={}'
      '\n\tZAP_HOME={}'
      '\n\tSCRIPTS_PATH={}'
      '\n\tSESSION_NAME={}'
      '\n\tCONTEXT_NAME={}'
      '\n\tINCLUDE_URLS={}'
      '\n\tEXCLUDE_URLS={}'
      '\n\tSTARTING_POINT={}'
      '\n\tREPORT_NAME={}'
      '\n\tAUTH={}'
      '\n\tUSE_AJAX_SPIDER={}'
      '\n\tADDITIONAL_URLS={}'
      .format(zap_proxy_home,
              build_id,
              zap_host,
              zap_port,
              zap_home,
              scripts_path,
              session_name,
              context_name,
              include_urls,
              exclude_urls,
              starting_point,
              report_name,
              authMethod,
              useAjaxSpider,
              additional_urls
              ))

if scripts_path is not None and len(scripts_path) > 0:
    # Check if scripts config file exists
    if not os.path.exists('{}/config.yaml'.format(scripts_path)):
        print('Scripts config file is not defined in: ', '{}/config.yaml'.format(scripts_path))
        exit(1)

    # Load scripts config.yaml from scripts path
    if scripts_path.endswith('/'):
        scripts_path = scripts_path[:-1]
    stream = open('{}/config.yaml'.format(scripts_path), 'r')
    scripts_config = load(stream, Loader=Loader)
'''
for config in scripts_config:
    for key, value in config.items():
        print('Key: {}, Value:{}'.format(key, value))
'''

#######################################
###       END VARIABLES             ###
#######################################

#######################################
###           START ZAP             ###
#######################################

# create zap home dir if not exists
zapDir = "{}/.ZAP_{}".format(zap_home, context_name)
if not os.path.exists(zapDir):
    try:
        os.makedirs(zapDir)
    except OSError:
        print("Creation of the directory %s failed" % zapDir)
    else:
        print("Successfully created the directory %s " % zapDir)

# Get environment platform
zap_executable_suffix = ''
if platform.system().lower() == 'windows':
    print('Current platform is Windows')
    zap_executable_suffix = '.bat'
elif platform.system().lower() == 'linux':
    print('Current platform is Linux')
    zap_executable_suffix = '.sh'
else:
    print('Unknown platform')
    exit(1)

zapSessionsFolder = '{}/sessions/{}_{}'.format(zap_home, session_name, build_id)
zap_cmd = '{zap_executable_path}/zap{suffix}'.format(zap_executable_path=zap_proxy_home, suffix=zap_executable_suffix)
zap_cmd_params = '-daemon -Xmx4G -port {port} -host {host} -dir {zapHomeDir} -config api.key={api_key} -config ' \
                 'database.request.bodysize=27035643 -config database.response.bodysize=27035643 -config ' \
                 'scanner.threadPerHost=2 -config connection.timeoutInSecs=60'.format(port=zap_port, host=zap_host,
                                                                                      api_key=apiKey, zapHomeDir=zapDir,
                                                                                      zapSession=zapSessionsFolder)
zap_cmd_params = [x for x in zap_cmd_params.split()]
zap_cmd_params.insert(0, zap_cmd)


def run_zap():
    # Build zap executable command line args
    global zap_cmd_params
    global zapStarted
    print("Executin zap proxy daemon")
    proc = subprocess.Popen(zap_cmd_params, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=zap_proxy_home,
                            universal_newlines=True, bufsize=1)
    time.sleep(5)
    for line in proc.stdout:
        if 'ZAP is now listening' in line:
            zapStarted = True
        print(line, end='')
    #######################################
    ###       END START ZAP             ###
    #######################################


def main():
    global zapStarted
    global zap_port
    global zap_host
    global zap_home
    global scripts_path
    global session_name
    global context_name
    global include_urls
    global exclude_urls
    global starting_point
    global report_name
    global authMethod
    global username
    global password
    global workspace
    global build_id
    global zap_proxy_home
    global additional_urls

    zap_thread = Thread(target=run_zap, daemon=True).start()
    # timeout and throw error after x time chosen by the user/default -> better 30 seconds default
    while not zapStarted:
        print("Zap is starting...")
        time.sleep(5)
    print('Zap started!')
    #######################################
    ###        CONFIGURATIONS           ###
    #######################################
    localProxy = {"http": "http://{}:{}".format(zap_host, zap_port), "https": "http://{}:{}".format(zap_host, zap_port)}
    isNewSession = True
    sessionName = session_name
    # Define the list of global exclude URL regular expressions. List can be empty.
    # The expressions must follow the java.util.regex.Pattern class syntax
    globalExcludeUrl = []
    # MANDATORY. Define if an outgoing proxy server is used
    useProxyChain = False

    # MANDATORY. Determine if context must be configured then used during scans.
    # You have to set this parameter to True if you want that ZAP performs scans
    # from the point of view of a specific user
    useContextForScan = True if authMethod is not None and len(authMethod) > 0 else False
    # MANDATORY only if useContextForScan is True. Ignored otherwise. Set value to
    # True to define a new context. Set value to False to use an existing one.
    defineNewContext = True
    # MANDATORY only if defineNewContext is True. Ignored otherwise
    contextName = context_name
    # MANDATORY only if defineNewContext is False. Disregarded otherwise.
    # Corresponds to the ID of the context to use
    contextId = 0
    # Define Context Include URL regular expressions. Ignored if useContextForScan
    # is False. You have to put the URL you want to test in this list.
    contextIncludeURL = include_urls.split(",") if include_urls is not None else sys.exit("Context url is required")
    # Define Context Exclude URL regular expressions. Ignored if useContextForScan
    # is False. List can be empty.
    contextExcludeURL = exclude_urls.split(',') if exclude_urls is not None else []
    # MANDATORY only if useContextForScan is True. Ignored otherwise. Define the
    # session management method for the context. Possible values are:
    # "cookieBasedSessionManagement"; "httpAuthSessionManagement"
    sessionManagement = 'cookieBasedSessionManagement'
    # MANDATORY only if useContextForScan is True. Ignored otherwise. Define
    # authentication method for the context. Possible values are:
    # "manualAuthentication"; "scriptBasedAuthentication"; "httpAuthentication";
    # "formBasedAuthentication"
    authMethod = authMethod if authMethod is not None and len(authMethod) > 0 else ''
    # MANDATORY only if useContextForScan is True. Ignored otherwise.
    # Set the value to True if a loggedin indicator must be used. False if it's a
    # logged out indicator that must be used
    isLoggedInIndicator = False
    # MANDATORY only if useContextForScan is True. Ignored otherwise.
    # Define either a loggedin or a loggedout indicator regular expression.
    # It allows ZAP to see if the user is always authenticated during scans.
    ####### Not used but required #######
    loggedinRegex = '\QYou are logged in as user\E'
    loggedoutRegex = '\QIf you want to sign in\E'
    # MANDATORY only if useContextForScan is True. Ignored otherwise.
    # Set value to True to create new users, False otherwise
    createUser = True if authMethod is not None and len(authMethod) > 0 else False
    # MANDATORY only if createUser is True. Ignored otherwise. Define the list of
    # users, with name and credentials (in x-www-form-urlencoded format)
    ## Here is an example with the script NashornTwoStepAuthentication.js:
    userList = []

    if authMethod is not None and len(authMethod) > 0:
        print('Add user')
        userList.append(
            {'name': '{}'.format(username), 'credentials': 'Username={}&Password={}'.format(username, password)})

    # MANDATORY only if useContextForScan is True. Ignored otherwise. List can be
    # empty. Define the userid list. Created users will be added to this list later
    userIdList = []
    # MANDATORY. Define the target site to test
    target = starting_point
    # You can specify other URL in order to help ZAP discover more site locations
    # List can be empty
    applicationURL = additional_urls.split(",") if additional_urls is not None and len(additional_urls) > 0 else []
    # MANDATORY. Set value to True if you want to customize and use a scan policy
    useScanPolicy = True
    # MANDATORY only if useScanPolicy is True. Ignored otherwise. Set a policy name
    scanPolicyName = 'SQL Injection and XSS'
    # MANDATORY only if useScanPolicy is True. Ignored otherwise.
    # Set value to True to disable all scan types except the ones set in ascanIds,
    # False to enable all scan types except the ones set in ascanIds..
    isWhiteListPolicy = True
    # MANDATORY only if useScanPolicy is True. Ignored otherwise. Set the scan IDs
    # to use with the policy. Other scan types will be disabled if
    # isWhiteListPolicy is True, enabled if isWhiteListPolicy is False.
    # Use zap.ascan.scanners() to list all ascan IDs.
    ## In the example bellow, the first line corresponds to SQL Injection scan IDs,
    ## the second line corresponds to some XSS scan IDs
    ascanIds = [40018, 40019, 40020, 40021, 40022, 40024, 90018,
                40012, 40014, 40016, 40017]
    # MANDATORY only if useScanPolicy is True. Ignored otherwise. Set the alert
    # Threshold and the attack strength of enabled active scans.
    # Currently, possible values are:
    # Low, Medium and High for alert Threshold
    # Low, Medium, High and Insane for attack strength
    alertThreshold = 'Low'
    attackStrength = 'High'

    # MANDATORY. Set True to shutdown ZAP once finished, False otherwise
    shutdownOnceFinished = False

    #################################
    ### END OF CONFIGURATIONS     ###
    #################################

    # Connect ZAP API client to the listening address of ZAP instance
    zap = ZAPv2(proxies=localProxy, apikey=apiKey)

    time.sleep(2)
    ## Get all ascand ids
    ascanIds = [x['id'] for x in zap.ascan.scanners()]

    # Start the ZAP session
    core = zap.core
    #################################
    print('Set zap mode')
    core.set_mode('standard')
    autoupdate = zap.autoupdate
    autoupdate.install_addon('spiderAjax')
    core.set_option_timeout_in_secs(60)
    #################################
    if isNewSession:
        pprint('Create ZAP session: ' + sessionName + ' -> ' +
               core.new_session(name=sessionName, overwrite=True))
    else:
        pprint('Load ZAP session: ' + sessionName + ' -> ' +
               core.load_session(name=sessionName))

    # Configure ZAP global Exclude URL option
    print('Add Global Exclude URL regular expressions:')
    for regex in globalExcludeUrl:
        pprint(regex + ' ->' + core.exclude_from_proxy(regex=regex))

    # Configure ZAP outgoing proxy server connection option
    pprint('Enable outgoing proxy chain: ' + str(useProxyChain) + ' -> ' +
           core.set_option_use_proxy_chain(boolean=useProxyChain))
    print(authMethod)
    if scripts_path is not None and len(scripts_path) > 0:
        print('Set other scripts')
        if scripts_config is not None and len(scripts_config) > 0:
            # Load all non authentication scripts
            for config in scripts_config:
                if config['type'] != 'authentication':
                    script = zap.script
                    script.remove(scriptname=config['name'])
                    pprint('Load script: ' + config['name'] + ' -> ' +
                           script.load(scriptname=config['name'], scripttype=config['type'],
                                       scriptengine=config['engine'],
                                       filename='{}/{}'.format(scripts_path, config['name']),
                                       scriptdescription=config['description']))
                    pprint('Enable script: ' + config['name'] + ' -> ' +
                           script.enable(scriptname=config['name']) if config[
                                                                           'enabled'] is True else 'Script not enabled')

    if useContextForScan:
        # Define the ZAP context
        context = zap.context
        if defineNewContext:
            contextId = context.new_context(contextname=contextName)
        pprint('Use context ID: ' + contextId)

        # Include URL in the context
        print('Include URL in context:')
        pprint(contextIncludeURL)
        for url in contextIncludeURL:
            pprint(url + ' -> ' +
                   context.include_in_context(contextname=contextName,
                                              regex=url))

        # Exclude URL in the context
        print('Exclude URL from context:')
        for url in contextExcludeURL:
            pprint(url + ' -> ' +
                   context.exclude_from_context(contextname=contextName,
                                                regex=url))

        # Setup session management for the context.
        # There is no methodconfigparams to provide for both current methods
        pprint('Set session management method: ' + sessionManagement + ' -> ' +
               zap.sessionManagement.set_session_management_method(
                   contextid=contextId, methodname=sessionManagement,
                   methodconfigparams=None))

        ## In case we use the scriptBasedAuthentication method, load the script
        if authMethod is not None and len(authMethod) > 0:
            pprint('Set authentication scripts...')
            auth = zap.authentication
            if authMethod == 'scriptBasedAuthentication':
                pprint('Set scriptBasedAuthentication...')
                if scripts_config is None or len(scripts_config) == 0:
                    print('No script for scriptBasedAuthentication provided')
                    exit(2)
                script = zap.script
                for config in scripts_config:
                    if config['type'] == 'authentication':
                        script.remove(scriptname=config['name'])
                        pprint('Load script: ' + config['name'] + ' -> ' +
                               script.load(scriptname=config['name'],
                                           scripttype=config['type'],
                                           scriptengine=config['engine'],
                                           filename='{}/{}'.format(scripts_path, config['name']),
                                           scriptdescription=config['description']))

                        # Define an authentication method with parameters for the context
                        auth_params = config['authData']
                        auth_params = auth_params.format(username=username, password=password)
                        auth_params = auth_params.replace(" ", "")
                        auth_params = auth_params.rstrip("\n")
                        pprint('Set authentication method: ' + str(authMethod) + ' -> ' +
                               auth.set_authentication_method(contextid=contextId,
                                                              authmethodname='scriptBasedAuthentication',
                                                              authmethodconfigparams=(
                                                                      'scriptName=' + config['name'] + '&'
                                                                      + auth_params)))
            # Define either a loggedin indicator or a loggedout indicator regexp
            # It allows ZAP to see if the user is always authenticated during scans
            if isLoggedInIndicator:
                pprint('Define Loggedin indicator: ' + loggedinRegex + ' -> ' +
                       auth.set_logged_in_indicator(contextid=contextId,
                                                    loggedinindicatorregex=loggedinRegex))
            else:
                pprint('Define Loggedout indicator: ' + loggedoutRegex + ' -> ' +
                       auth.set_logged_out_indicator(contextid=contextId,
                                                     loggedoutindicatorregex=loggedoutRegex))
        # Define the users
        users = zap.users
        if createUser:
            for user in userList:
                userName = user.get('name')
                print('Create user ' + userName + ':')
                userId = users.new_user(contextid=contextId, name=userName)
                userIdList.append(userId)
                pprint('User ID: ' + userId + '; username -> ' +
                       users.set_user_name(contextid=contextId, userid=userId,
                                           name=userName) +
                       '; credentials -> ' +
                       users.set_authentication_credentials(contextid=contextId,
                                                            userid=userId,
                                                            authcredentialsconfigparams=user.get('credentials')) +
                       '; enabled -> ' +
                       users.set_user_enabled(contextid=contextId, userid=userId,
                                              enabled=True))

    ###########################################

    # Enable all passive scanners (it's possible to do a more specific policy by
    # setting needed scan ID: Use zap.pscan.scanners() to list all passive scanner
    # IDs, then use zap.scan.enable_scanners(ids) to enable what you want
    pprint('Enable all passive scanners -> ' +
           zap.pscan.enable_all_scanners())

    ascan = zap.ascan
    # Define if a new scan policy is used
    if useScanPolicy:
        ascan.remove_scan_policy(scanpolicyname=scanPolicyName)
        pprint('Add scan policy ' + scanPolicyName + ' -> ' +
               ascan.add_scan_policy(scanpolicyname=scanPolicyName))
        for policyId in range(0, 5):
            # Set alert Threshold for all scans
            ascan.set_policy_alert_threshold(id=policyId,
                                             alertthreshold=alertThreshold,
                                             scanpolicyname=scanPolicyName)
            # Set attack strength for all scans
            ascan.set_policy_attack_strength(id=policyId,
                                             attackstrength=attackStrength,
                                             scanpolicyname=scanPolicyName)
        if isWhiteListPolicy:
            # Disable all active scanners in order to enable only what you need
            pprint('Disable all scanners -> ' +
                   ascan.disable_all_scanners(scanpolicyname=scanPolicyName))
            # Enable some active scanners
            pprint('Enable given scan IDs -> ' +
                   ascan.enable_scanners(ids=ascanIds,
                                         scanpolicyname=scanPolicyName))
        else:
            # Enable all active scanners
            pprint('Enable all scanners -> ' +
                   ascan.enable_all_scanners(scanpolicyname=scanPolicyName))
            # Disable some active scanners
            pprint('Disable given scan IDs -> ' +
                   ascan.disable_scanners(ids=ascanIds,
                                          scanpolicyname=scanPolicyName))
    else:
        print('No custom policy used for scan')
        scanPolicyName = None

    # Open URL inside ZAP
    pprint('Access target URL ' + target)
    core.access_url(url=target, followredirects=True)
    for url in applicationURL:
        pprint('Access URL ' + url)
        core.access_url(url=url, followredirects=True)
    # Give the sites tree a chance to get updated
    time.sleep(2)

    # Launch Spider, Ajax Spider (if useAjaxSpider is set to true) and
    # Active scans, with a context and users or not
    forcedUser = zap.forcedUser
    spider = zap.spider
    ajax = zap.ajaxSpider
    scanId = 0
    print('Starting Scans on target: ' + target)
    if useContextForScan:
        for userId in userIdList:
            print('Starting scans with User ID: ' + userId)

            # Spider the target and recursively scan every site node found
            scanId = spider.scan_as_user(contextid=contextId, userid=userId,
                                         url=target, maxchildren=None, recurse=True, subtreeonly=None)
            print('Start Spider scan with user ID: ' + userId +
                  '. Scan ID equals: ' + scanId)
            # Give the spider a chance to start
            time.sleep(2)
            while int(spider.status(scanId)) < 100:
                print('Spider progress: ' + spider.status(scanId) + '%')
                time.sleep(2)
            print('Spider scan for user ID ' + userId + ' completed')

            if useAjaxSpider:
                # Prepare Ajax Spider scan
                pprint('Set forced user mode enabled -> ' +
                       forcedUser.set_forced_user_mode_enabled(boolean=True))
                pprint('Set user ID: ' + userId + ' for forced user mode -> ' +
                       forcedUser.set_forced_user(contextid=contextId,
                                                  userid=userId))
                # Ajax Spider the target URL
                ajax.set_option_max_crawl_depth(5)
                ajax.set_option_max_duration(5)
                start_ajax_time = datetime.now()
                pprint('Ajax Spider the target with user ID: ' + userId + ' -> ' +
                       ajax.scan(url=target, inscope=None, subtreeonly=True))
                # Give the Ajax spider a chance to start
                time.sleep(10)
                while ajax.status != 'stopped':
                    current_ajax_time = datetime.now() - start_ajax_time
                    print(
                        '[{}][Running from {}s] Ajax Spider is: {}'.format(datetime.now().strftime("%d/%m/%y %H:%M:%S"),
                                                                           int(current_ajax_time.total_seconds()),
                                                                           ajax.status))
                    if (current_ajax_time.total_seconds() / 60) > int(ajax_timeout):
                        ajax.stop()
                    time.sleep(10)
                for url in applicationURL:
                    start_ajax_time = datetime.now()
                    # Ajax Spider every url configured
                    pprint('Ajax Spider the URL: ' + url + ' with user ID: ' +
                           userId + ' -> ' +
                           ajax.scan(url=url, inscope=None))
                    # Give the Ajax spider a chance to start
                    time.sleep(10)
                    while ajax.status != 'stopped':
                        current_ajax_time = datetime.now() - start_ajax_time
                        print('Ajax Spider is ' + ajax.status)
                        if (current_ajax_time.total_seconds() / 60) > int(ajax_timeout):
                            ajax.stop()
                        time.sleep(5)
                pprint('Set forced user mode disabled -> ' +
                       forcedUser.set_forced_user_mode_enabled(boolean=False))
                print('Ajax Spider scan for user ID ' + userId + ' completed')

            # Launch Active Scan with the configured policy on the target url
            # and recursively scan every site node
            print('Stating the active scan...')
            time.sleep(5)
            scanId = ascan.scan_as_user(url=target, contextid=contextId,
                                        userid=userId, recurse=True, scanpolicyname=scanPolicyName,
                                        method=None, postdata=True)
            print('Start Active Scan with user ID: ' + userId +
                  '. Scan ID equals: ' + scanId)
            # Give the scanner a chance to start
            time.sleep(5)
            while int(ascan.status(scanId)) < 100:
                print('Active Scan progress: ' + ascan.status(scanId) + '%')
                time.sleep(5)
            print('Active Scan for user ID ' + userId + ' completed')

    else:
        # Spider the target and recursively scan every site node found
        scanId = spider.scan(url=target, maxchildren=None, recurse=True,
                             contextname=None, subtreeonly=None)
        print('Scan ID equals ' + scanId)
        # Give the Spider a chance to start
        time.sleep(2)
        while int(spider.status(scanId)) < 100:
            print('Spider progress ' + spider.status(scanId) + '%')
            time.sleep(2)
        print('Spider scan completed')

        if useAjaxSpider:
            # Ajax Spider the target URL
            pprint('Start Ajax Spider -> ' + ajax.scan(url=target, inscope=None))
            # Give the Ajax spider a chance to start
            start_ajax_time = datetime.now()
            time.sleep(10)
            while ajax.status != 'stopped':
                current_ajax_time = datetime.now() - start_ajax_time
                print('Ajax Spider is ' + ajax.status)
                if (current_ajax_time.total_seconds() / 60) > int(ajax_timeout):
                    ajax.stop()
                time.sleep(5)
            for url in applicationURL:
                # Ajax Spider every url configured
                start_ajax_time = datetime.now()
                pprint('Ajax Spider the URL: ' + url + ' -> ' +
                       ajax.scan(url=url, inscope=None))
                # Give the Ajax spider a chance to start
                time.sleep(10)
                while ajax.status != 'stopped':
                    current_ajax_time = datetime.now() - start_ajax_time
                    print('Ajax Spider is ' + ajax.status)
                    if (current_ajax_time.total_seconds() / 60) > int(ajax_timeout):
                        ajax.stop()
                    time.sleep(5)
            print('Ajax Spider scan completed')

        # Launch Active scan with the configured policy on the target url and
        # recursively scan every site node
        scanId = zap.ascan.scan(url=target, recurse=True, inscopeonly=None,
                                scanpolicyname=scanPolicyName, method=None, postdata=True)
        print('Start Active scan. Scan ID equals ' + scanId)
        while int(ascan.status(scanId)) < 100:
            print('Active Scan progress: ' + ascan.status(scanId) + '%')
            time.sleep(5)
        print('Active Scan completed')

    # Give the passive scanner a chance to finish
    print('Waiting for scanner to finish...')
    time.sleep(10)

    # If you want to retrieve alerts:
    # pprint(zap.core.alerts(baseurl=target, start=None, count=None))

    # Create reports dir
    if workspace.endswith('/'):
        workspace = workspace[:-1]
    reports_path = '{reportPath}/reports'.format(reportPath=workspace)
    if not os.path.exists(reports_path):
        try:
            os.makedirs(reports_path)
        except OSError:
            print("Creation of the directory %s failed" % reports_path)
        else:
            print("Successfully created the directory %s " % reports_path)

    # To retrieve ZAP report in XML or HTML format
    ## print('XML report')
    ## core.xmlreport()
    print('HTML report:')
    # pprint(core.htmlreport())
    with open('{reportPath}/{reportName}_{buildId}.html'.format(reportPath=reports_path, reportName=report_name,
                                                                buildId=build_id), "w") as f:
        f.write(core.htmlreport())
    with open('{reportPath}/{reportName}_{buildId}.xml'.format(reportPath=reports_path, reportName=report_name,
                                                               buildId=build_id), "w") as f:
        f.write(core.xmlreport())
    time.sleep(5)
    pprint('Scan completed. Report: -> '
           + '\n{reportPath}/{reportName}_{buildId}.html'.format(reportPath=reports_path, reportName=report_name,
                                                                 buildId=build_id)
           + '\n{reportPath}/{reportName}_{buildId}.xml'.format(reportPath=reports_path, reportName=report_name,
                                                                buildId=build_id))
    # Shutdown ZAP once finished
    pprint('Shutdown ZAP -> ' + core.shutdown())
    exit(0)


if __name__ == '__main__':
    main()