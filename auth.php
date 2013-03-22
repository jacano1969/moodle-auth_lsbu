<?php

if (!defined('MOODLE_INTERNAL')) {
    die('Direct access to this script is forbidden.');
}

require_once($CFG->libdir.'/authlib.php');

/*
 * LSBU authentication plugin.
 */
class auth_plugin_lsbu extends auth_plugin_base {

    function init_plugin($authtype) {
        $this->pluginconfig = 'auth/'.$authtype;
        $this->config = get_config($this->pluginconfig);
        
        if (empty($this->config->lsbu_hash)) {
             $this->config->lsbu_hash = '';
        }
    }

    function auth_plugin_lsbu() {
        $this->authtype = 'lsbu';
        $this->roleauth = 'auth_lsbu';
        $this->init_plugin($this->authtype);
    }

    function user_login($username, $password=null) {

        if (!$username) {
            return false;
        }

        if ($this->lsbu_login_check()==true) {
            return true;
        }
        return false;
    }

    // not using a data synch
    function prevent_local_passwords() {
        return false;
    }

    function is_internal() {
        return true;
    }

    // do not allow password updates
    function user_update_password($user, $newpassword) {
        return false;
    }
    
    // do not allow password change
    function can_change_password() {
        return false;
    }

    // do not allow password reset
    function can_reset_password() {
        return false;
    }
    
    
    function loginpage_hook() {
        global $CFG, $SESSION;

        if (isset($SESSION->wantsurl)) {
            
            $request_str='';
            $username='';
            $ts='';
            $token='';
            
            // get the current timstamp
            list($unixtime, $seconds) = explode(" ", microtime());
            $timestamp = sprintf('%d%03d', $seconds, $unixtime/1000);
            
            // grap request vars
            $request_str=parse_url($SESSION->wantsurl);

            // put in an array
            if(!empty($request_str['query'])) {
                $request_vars = explode("&",$request_str['query']);
            } else {
                return;
            }
            
            // get required vars
            foreach($request_vars as $request_var) {
                
                // get each var and value 
                $this_request_var = explode("=",$request_var);
                
                if(strtoupper($this_request_var[0])=="U") {
                    $username = $this_request_var[1];
                }
                
                if(strtoupper($this_request_var[0])=="TS") {
                    $ts = $this_request_var[1];
                }
                
                if(strtoupper($this_request_var[0])=="TOKEN") {
                    $token = $this_request_var[1];
                }
            }
            
            // check we have evertything required
            if($username!='' && $ts!='' && $token!='') {
                
                $compare_ts = '';
                $compare_timestamp = '';
                
                $compare_timestamp = substr($timestamp,0,10);
                $compare_ts = substr($ts,0,10);
                
                if($compare_ts <= $compare_timestamp) {
                    
                    $secret = $this->config->lsbu_hash;
                    
                    // create hash
                    $str = $secret . $username . $ts;
                    $hashed_str = strtoupper(sha1($str));
                        
                    $CFG->nolastloggedin = true;
                    
                    // check that sha1 values match
                    if($token==$hashed_str) {
                        
                        global $USER;
                        
                        // authenticate user
                        //$user = authenticate_user_login($username,null);
                        if ($user = get_complete_user_data('username', $username, $CFG->mnet_localhost_id)) {
                            
                            add_to_log(SITEID, 'user', 'login', "view.php?id=$USER->id&course=".SITEID,
                                       $user->id, 0, $user->id);
                         
                            complete_user_login($user);
                        } 
                    }
                }
            }
        }
    
        // now real test login
        if (isloggedin() && !isguestuser()) {
            if (isset($SESSION->wantsurl) and (strpos($SESSION->wantsurl, $CFG->wwwroot) === 0)) {
                $urltogo = $SESSION->wantsurl;
                unset($SESSION->wantsurl);
    
            } else {
                $urltogo = $CFG->wwwroot.'/';
                unset($SESSION->wantsurl);
            }
    
            redirect($urltogo);
        }
    
        // do not show user credentials if user logs out
        $CFG->nolastloggedin = true;
    
        return;
    }
    
    function config_form($config, $err, $user_fields) {
        global $CFG, $OUTPUT;

        include($CFG->dirroot.'/auth/lsbu/config.html');
    }

    // proces and store config data
    function process_config($config) {
        
        if (!isset($config->lsbu_hash)) {
             $config->lsbu_hash = '';
        }

        // Save settings
        set_config('lsbu_hash', trim($config->lsbu_hash), $this->pluginconfig);

        return true;
    }
}

