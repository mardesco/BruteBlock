<?php

/**
 * Plugin Name: BruteBlock
 *
 * Description: A blunt instrument for blocking brute force attacks.  Permanently bans IP addresses involved in a brute force attack against a WordPress installation.  Bans visitors with spoofed auth cookies.  Also denies access to users listed in the Stop Forum Spam registry.  Can be used in conjunction with other WordPress login security plugins.
 * 
 *
 * Plugin URI: https://github.com/mardesco/BruteBlock/
 * Version: beta 0.4.1
 * Author: Jesse Smith
 * Author URI: http://www.jesse-smith.net/
 * License: GPL
 * @package BruteBlock
 * 
 * Notes:
 * This plugin includes the StopForumSpam blacklist, available from StopForumSpam.com
 * 
 * This plugin also includes GeoLite country data created by MaxMind, available from http://www.maxmind.com
 * 
 * 
 */


 
 /*
 BruteBlock is a work in progress.  Test it, play around with it, but use it on mission-critical websites at your own risk.
 
 If you have any suggestions, ideas, or corrections, please contact me.
 
 
 Known issues as of 7-5-13:
 
 1.  internal method is_login_page returns false on a multisite installation, even when the attacker is hitting the login page.
 
 2.  internal methods bb_bad_auth_cookie and bb_check_malformed block legitimate user when the website is running the wp-e-commerce shopping cart plugin.
 When a legitimate user adds an item to the shopping cart, the lengthy cookie is treated as a malformed login cookie and the visitor is insta-banned.
 Incorrectly.
 
 3. it appears that the script is triggered even when the attacker sees a 403 because of an .htaccess deny rule.  
 4. (possibly resolved): multiple block notifications for the same attacker (should never get more than one notification because after the first one, they're blocked).
 
 */
 

/*
 * The main file for BruteBlock
 */

$GLOBALS['BruteBlock'] = new BruteBlock;//instantiate a global object.

class BruteBlock{
    
    protected $_message;
    protected $_ip;
    protected $_ban_list;//these are PERMANENT
    protected $_temp_block_list;//possibly legitimate users will get another chance.
    protected $_stop_forum_spam_list;//courtesy of StopForumSpam - with many, many thanks!
    protected $_dir_base;
    protected $_max_allowed_failed_logins; 
    protected $_max_allowed_blocks; 
    protected $_min_timeout;
    protected $_clear_after; 
    protected $_use_sleep;
    protected $_is_login;
    protected $_maxmind;
    //protected $_country;
	protected $_reason;
        


public function __construct(){
	
	//prevent disclosure of filepath if errors occur
	ini_set('display_errors', 'Off');

    //use the WordPress hooks to call our functions.
    add_action('init', array(&$this, 'bb_startup'));//initial check

    //we have zero tolerance for bad cookies.  Legitimate users don't have this problem...  except maybe sometimes if they have network connectivity issues.  Automatic permanent ban.
    add_action('auth_cookie_bad_username', array(&$this, 'bb_bad_auth_cookie'), 1);
    add_action('auth_cookie_bad_hash', array(&$this, 'bb_bad_auth_cookie'), 1);
	
	//auth_cookie_malformed is also invoked on NO cookies, which presents a problem
	//because you don't want legit users to get insta-banned just for the common practice of accessing the login page by typing in /wp-admin/
	//so we call a different function here.
	add_action('auth_cookie_malformed', array(&$this, 'bb_check_malformed'), 1, 2);	

    //process a failed login.  Is it a brute?  Or is it a legitimate user who simply typed their password wrong?
    add_action('wp_login_failed', array(&$this, 'bb_process_login_errors'));
	
	//obscure the login error message.  Other security plugins may override this with their own message, and that's fine.
    add_filter('login_errors', array(&$this, 'bb_change_login_error_message'));

    //and finally, what to do when the user successfully logs in with valid credentials
    add_action('wp_login', array(&$this, 'bb_process_login_attempt'));//don't let them log in if they're on the temp block list: even if they finally figure out the correct info
    
	//now we define the location of our various lists and directories
	
	$base = dirname(__FILE__);
	
	//for compatibility with Windows...
	$separator = strpos($base, '/') !== false ? '/' : "\\";//only want one slash here, but have to escape it to avoid parse errors.
	
	$this->_dir_base = $base . $separator;
	
    //location of our permanent ban list
    $this->_ban_list = $this->_dir_base . 'permanent_ban.csv';//unfriendly addresses will be dynamically added to this list      
    
    //location of the Stop Forum Spam list
    $this->_stop_forum_spam_list = $this->_dir_base . 'bannedips.csv';//you can update this list when new lists are available.
    
    //location of our temporary block list 
    $this->_temp_block_list = $this->_dir_base . 'temp_block.csv';//the list of IPs "on probation" - gets dynamically updated
    
    //new as of version 0.3!  the path to the MaxMind list, which associates an IP with a location!
    $this->_maxmind = $this->_dir_base . 'MaxMind-US-IPs-min.csv';

    // initial message is...  no message.
    $this->_message = '';    
	
	$this->_reason = '';
    
    // same for country.
    //$this->_country = '';//the file was too large.  we're not doing it that way at this time.
    
    
    //some config options
    //TODO: need a way to store user settings, to allow modification to max_allowed and min_timeout from the admin area
    //but for today...

    $this->_max_allowed_failed_logins = 2;//they can get it wrong twice.  3 strikes and they're out.
	
	//how many times they can be blocked before invoking a permanent ban.  
    $this->_max_allowed_blocks = 1;// restrictive default: second lockout triggers permanent ban!
    
	//If they are temporarily blocked and continue trying to log in before min_timeout expires, they will be permanently banned.
	$this->_min_timeout = 60 * 60 * 24;//1 day.  
    $this->_clear_after = 60 * 60 * 24 * 21; //temp log resets after three weeks.  In case legit users forget their passwords.    
    
	
	//possible conflict: 
	//if BruteBlock is activated on a server with the "Login Security Solution" plugin running, 
	//there could be a timeout PHP fatal error, if both scripts call sleep() and the combined total exceeds the maximum execution time.
	//to prevent this, let's detect the other plugin and store our value here.
	//NOTE: there are several additional plugins that have not been tested with BruteBlock!
	//if your security plugin calls sleep() then you should test it with is_plugin_active('your-plugin.php') below!
	$this->_use_sleep = true;
	if(is_admin() || $this->is_login_page()){
            
                $this->_is_login = true;
	
		if(!function_exists('is_plugin_active')){
			include_once( ABSPATH . 'wp-admin/includes/plugin.php' );//per WP codex... 
			}
		if(is_plugin_active('login-security-solution/login-security-solution.php')){
			$this->_use_sleep = false;
			}
                }else{
                    
                    $this->_is_login = false;
                }
	
    
    //and finally, let's find out who our visitor is.
    
    if(empty($_SERVER['REMOTE_ADDR'])){ 
        $remote_ip = '';
    }else{
        $remote_ip = $_SERVER['REMOTE_ADDR'];//if you are using a reverse proxy, then you're too fancy for this plugin.  We're just plain vanilla here.
    }
    if(!is_string($remote_ip)){
        $remote_ip = '';
    }else{
        $remote_ip = trim($remote_ip);   
    }

    if($remote_ip == ''){
		//why can't we see their IP address?  Who cares?  Nice people don't hide this information.
        // well, I suppose it's possible that this could accidentally be triggered by a misconfigured server.  
		// If this happens to you, delete this line or upgrade your server.
		$this->_reason .= "The visitor's IP address was obscured, obfuscated, or otherwise unavailable.  ";
		
        $this->block_the_brute();
    }else{
        $this->_ip = $remote_ip;
    }    
}

protected function bb_bad_auth_cookie(){
	$this->_reason .= "User sent invalid auth cookie data.  Probable cookie forgery.  Insta-ban.  
	
	Note: there is a small chance that network connectivity issues interfered with data transmission, resulting in the ban of a legitimate user.  If that's the case, you will need to edit the ban list and manually remove the above IP address.  ";
	
	//insta-ban!
	$this->bb_add_to_ban_list();
}

//since there isn't a function for this built into the WP core....  yet...
private function is_login_page() {

	$current_uri = esc_url( $_SERVER['REQUEST_URI'], array('http', 'https') );
	if(!$current_uri || $current_uri == ''){
		$this->_reason .= 'Bad protocol (ie neither http nor https) or otherwise invalid request uri. ';
		$this->block_the_brute();//say no to bad protocol or invalid request uri
	}
	
	// strpos: haystack, needle.
	if(strpos($current_uri, 'login.php') !== false || strpos($current_uri, 'register.php') !== false){
		return true;
	}
	
	//the final line of this method is courtesy of commenter at 
	//http://stackoverflow.com/questions/5266945/wordpress-how-detect-if-current-page-is-the-login-page
	//....but it erroneously returns false on multisite!!!  
	//why?  I have no idea.  I just know that this next line, acting on its own, failed to stop an attacker in the wild.
	//which is why I added the above check to the request uri.
    return in_array($GLOBALS['pagenow'], array('wp-login.php', 'wp-register.php'));
}

private function is_comment_submission(){

	return in_array($GLOBALS['pagenow'], array('wp-comments-post.php'));
}

public function bb_startup(){

    //first, check the remote IP to see if it's already banned.
    //this will prevent banned users from accessing the FRONT END of your site too.  
    //this makes it harder for them to spam up your comment threads or seek other exploits.    
    if($this->bb_in_ban_list($this->_ip)){//actually checks two different lists.
	
		$this->_reason .= "The visitor's IP address was on a list of banned IPs.  ";
	
        $this->block_the_brute();//lock out blocked IPs.
        exit();
    }
    
	$is_comment_submission = $this->is_comment_submission();
	
    //next, let's see if this is someone trying to log in or submit comments from the wrong country.
    if($this->_is_login || $is_comment_submission){
            $passed = $this->bb_is_user_in_us();

            //as of version 0.3:
            //users outside the US may not access the login page, ever.  They will be banned.
            if(!$passed){
                
				if($this->_is_login){
				
				$this->_reason .= "Visitor attempted to log in from outside the permitted geographical area.  Insta-ban.  ";
				
                // insta-ban!
                $this->bb_add_to_ban_list();
				}else{
				//we're a little nicer to commenters.  
				//it might be a legitimate user in Britain or Canada who wanted to make a relevant comment.
				
				$this->_reason .= "Visitor attempted to submit a comment from outside the permitted geographical area.  ";				
				
				//TODO:  implement this plugin: http://wordpress.org/extend/plugins/comment-email-verify/ and delete the following.
				
	//resolve conflicts with other plugins.
	add_action('shutdown', array($this, 'bb_kill_scripts'), 1);

	die("<h1>Sorry</h1><p>Due to massive spam infestations, users from your region are not permitted to post comments.</p>");	
				
				}//end "it was a comment
                
            }//end "they're not in the US"
        
    }//end "it was a login or a comment"
	
}

protected function bb_is_user_in_us(){
    
        //check their IP address against the list from MaxMind.
        //Note that the actual Maxmind list was TOO BIG!
		// this system is using a custom-edited list
		//that only shows US addresses.
		//so we can match someone in the US
		//but we cannot ID the country of someone outside the US.
		//TODO: figure out a way to make that work.
		
		
        //cheers to Pepak's IP-to-Country WordPress plugin for this idea.  www.pepak.net
        //
        //first, are they using IPv4?  this work-in-progress beta release does not yet deal with IPv6.
        if(!stristr($this->_ip, ':')){//not IPv6
            
            $long_ip = ip2long($this->_ip);
            
            //not sure why this would happen, but just in case:
            if(!$long_ip || $long_ip == ''){return false;}
            
        }//else: need to write a way to figure their location for IPv6.
        else{
            //for now, let's assume they're using IPv6 to escape detection.
            //this obviously needs to be updated.
            //TODO:  FIX THE IPV6 HANDLING!!!
			
			$this->_reason .= "Visitor was using IPv6.  This system does not support IPv6.  Therefore, this user is presumed to use IPv6 to escape detection.  ";
			
            return false;
            
        }
        
            
            //now we have their long ip.  
            //next, we have to find that number
            //between the ip_from and the ip_to columns
            //in the MaxMind .csv        
        
        $maxmind = $this->_maxmind;
        
        $visitor_country_code = false;//pessimistic initial default.
        
        // based on the manual at http://us3.php.net/manual/en/function.fgetcsv.php
        if (($handle = fopen($maxmind, "r")) !== FALSE) {
            while (($data = fgetcsv($handle, 1024, ",")) !== FALSE) {
			
			
			//new csv structure:
			//0 is beginning IP in range
			//1 is ending IP in range
			//and that's it.

                if($long_ip >= $data[0] && $long_ip <= $data[1]){

                    return true;

                }
            }//end while
            fclose($handle);
        }//end fopen

		//if it did not already return true, then their IP was not found in the list.
        return false;
}

protected function block_the_brute(){
    //TODO: add a logging feature so we know who was blocked...
    
	if($this->_use_sleep){
		sleep(24);//make them wait for it.
		}
    
    //we're not interested in being nice.
    if(!headers_sent()){
        header('HTTP/1.1 403 Forbidden');
        ?><!doctype html>
            <html>
            <head>
                <title>403 Forbidden</title>
            </head>
            <body>
                <h1>Forbidden</h1>
                <p>You do not have permission to access this resource on this server.</p>
            </body>
            </html><?php
            exit();
    }else{die("Unauthorized access denied.");}
    
}


protected function bb_check_list($file, $ip){
  if(is_file($file)){
        
		// this function is crucial to the functioning of BruteBlock
		// so naturally it has caused me an unexpected number problems.
		
		// first there was a logical error.  Fixed that.
		// Then file_get_contents worked on my test server
		// but I run out of allocated memory on shared hosting!  Fatal error, no good.
		// (insert cursing here)
		
		// After that I figured we'll have to read the darn file one line at a time.
		// But NO.  this takes too long.  Almost 0.65 second on some requests.  Unacceptable.
		
		// so I'm back to using file_get_contents, but this time with unset called in hopes that it will prevent the memory error.
		// props to ZB Block for the idea.
		
		$data = file_get_contents($file);//we're hopeful that this will not exceed the memory allocation on your shared hosting account.
		
		
		//version beta.0.4 had to reformat the entire ban list to make this work.
		//MUST have commas both before and after the IP to avoid a false positive!
		$ip_string = "," . $ip . ",";
		
		if(strpos($data, $ip_string) !== false){
			unset($data);//save memory!
			return true;//they're on the list: block them!
		}
		
	unset($data);	// save memory!
		
    }else{
		die("");// $file is not available.
	}  		
	// the visitor's IP address was not found on the supplied list.
    return false;//keep checking.

}

private function bb_in_ban_list($ip){
	
    //let's check our own ban list first.
    if($this->bb_check_list($this->_ban_list, $ip)){
        return true;
    }
    
    //next we'll check a much larger list from Stop Forum Spam
    if($this->bb_check_list($this->_stop_forum_spam_list, $ip)){
        return true;
    }
    
    //no matches found yet.
    return false;
}

public function bb_check_temp_list(){
    
$remote_ip = $this->_ip;
    
    //our csv file has four fields: the IP, the number of times it has been blocked, the number of failed logins, and the last block timestamp
    
	//this function had been using bb_check_list
	// but THAT function now uses commas before & after the IP address.
	
	//if($this->bb_check_list($this->_temp_block_list, $remote_ip)){
	
        //test temp list to see if they are already on the watch list for previous login failures.
        
        //how many times have they been blocked?  we have to find the actual line in our csv file.
		//if the answer is zero, return an empty array.
		
		$foundit = false;
		
      if (($handle = fopen($this->_temp_block_list, "r")) !== FALSE) {
        while (($data = fgetcsv($handle, 1024, ",")) !== FALSE) {

            if(in_array($remote_ip, $data)){//this is the line we're looking for.
                
				$foundit = true;
				
                //data[0] is the ip, which we already know.
                
                //data[1] is the number of temporary blocks
                $block_count = $data[1];
                
                //data[2] is the number of failed logins since the last reset
                $fail_count = $data[2];
                
                //data[3] is the timestamp
                $last_block_time = $data[3];

            }

        }
        fclose($handle);
    }        
        
	if(!$foundit){
		//first time blocker, long time hacker
		return array();
	}
        

        
        if($block_count > $this->_max_allowed_blocks){//yer OUTTA here!
		
			$this->_reason .= "Too many failed logins.  ";
		
            $this->bb_remove_from_temp_list();
            $this->bb_add_to_ban_list();//calls block_the_brute()
            exit();
        }    
    
       $tmp_block_info = array('ip'=>$remote_ip, 'block_count'=> $block_count, 'fail_count'=>$fail_count, 'last_block_time'=>$last_block_time);

    //}//end if bb_check_list($temp_list)
    //else{
    //    $tmp_block_info = array();
    //}
       return $tmp_block_info;
}

public function bb_process_login_attempt(){//this function is called on an otherwise SUCCESSFUL LOGIN
    //check to see if they have been TEMPORARILY blocked.    
    
	
				//invoke the temporary block.  disallow access until timeout expires.  
                //if they persist, they will be banned permanently.	
	
    $temped = $this->bb_check_temp_list();
    if($temped){
    
        $block_count = $temped['block_count']; 
        $fail_count = $temped['fail_count'];
        $last_block_time = $temped['last_block_time'];
        
        if($fail_count > $this->_max_allowed_failed_logins){
            //they have had several successive login failures
			//before we block them, we have to know if the timeout has expired.  

            //how recent was their last block?
            $current_time = time();
            $elapsed_time = $current_time - $last_block_time;
            
            if($elapsed_time < $this->_min_timeout){
			
			//no.  changing the logic here.  if they've been blocked and then they guess the correct login,
			//add them to the permanent ban list.
			
			//should probably also force a password reset for the affected user...  but other plugins already do that.
			
			
			
			
                
                //NOTE: This feature could potentially frustrate some legitimate users who have trouble using computers!
                //What can we say?  If you have clients like that...  don't install this plugin on their website.  Or charge them extra to rescue them.  It's better than getting pwned.
                $block_count += 1;
                $this->bb_update_temp_list($this->_ip, $block_count, $fail_count, time());
                $this->_message = '<strong>Too many failed logins.</strong>';
				//You <em>must</em> wait 24 hours before trying again.;//if you make the min_timeout dynamic, then this has to be also.
				
				$this->_reason .= "Successful login after too many failed logins.  You should reset your password immediately!!  ";				
                
				//they had been temporarily blocked.  they continued to try to log in.  ban them.
				$this->bb_convert_temp_to_perm();//forces a logout, adds them to permanent block list.
            }else{
                //they waited for $min_timeout and logged in with the correct credentials.
                //other plugins may still force a password reset; but as far as BruteBlock is concerned, they are a legitimate user.
                //(we recommend running this plugin concurrently with something more refined, such as Login Security Solution, which also looks at their network and other signatures)
                $fail_count = 0;

                if($elapsed_time >= $this->_clear_after){
                    $block_count = 0;
                }
                $this->bb_update_temp_list($this->_ip, $block_count, $fail_count, $last_block_time);
            }
            
        }else{
			//reset the fail count for a successful login.
			$fail_count = 0;
			$this->bb_update_temp_list($this->_ip, $block_count, $fail_count, $last_block_time);
		}

    }//end if temped.  
    
}//end bb_process_login_attempt    


public function bb_kill_scripts(){
	//another plugin is causing a conflict.
	//if it happens to me, it will happens to others.
	//this rather brutal workaround seems to solve the issue without ever properly diagnosing it.
	exit();
}

protected function bb_test_for_temporary_ban(){
//because this is called more than once, it gets its own function.

    //so first we check to see if they are already in the TEMPORARY ban list.
    $temped = $this->bb_check_temp_list();
	

    if($temped){
    //if so, see if they have exceeded the max_allowed in less than the timeout    
        $block_count = $temped['block_count']; 
        $fail_count = $temped['fail_count'];
		$fail_count += 1;//increment this, because they just failed again.
		
        $last_block_time = $temped['last_block_time'];    
    
        if($fail_count > $this->_max_allowed_failed_logins){
            //they have had several successive login failures; but before we block them, we have to know if the timeout has expired.  
			//this allows us to give legitimate users another chance.

            //how recent was their last block?
            $current_time = time();
            $elapsed_time = $current_time - $last_block_time;
            
            if($elapsed_time < $this->_min_timeout || $last_block_time == 0){//they did not wait, or this is their first block.
                $block_count += 1;
                if($block_count > $this->_max_allowed_blocks){
                    //kick them out permanently.
					$this->_reason .= "Too many failed logins.  ";					
					
                    $this->bb_remove_from_temp_list();//housekeeping.
                    $this->bb_add_to_ban_list();//calls block_the_brute
                
                }

                //they haven't failed enough times to invoke the permanent ban.
                //invoke the temporary block.  disallow access until timeout expires.  
                //if they persist, they will be banned permanently.
                //NOTE: This feature could potentially frustrate some legitimate users who have trouble using computers!
                //What can we say?  If you have clients like that...  don't install this plugin on their website.  Or charge them extra to rescue them.  It's better than getting pwned.

                $this->bb_update_temp_list($this->_ip, $block_count, $fail_count, time());
                $this->_message = '<strong>Too many failed logins.</strong>';
				//  <strong>You <em>must</em> wait 24 hours before trying again. // don't give them this information
               //? not necessary to log them out: they didn't succeed in logging in.  right?
            }else{
                $fail_count = 1;//they waited like they were supposed to.  start over at 1 in case it's a legitimate user.
                $this->bb_update_temp_list($this->_ip, $block_count, $fail_count, $last_block_time);                
            }   

    
    }else{
        //this is not their first failed login, but they haven't been blocked yet.
        $this->bb_update_temp_list($this->_ip, $block_count, $fail_count, $last_block_time);
        
    } 
        
    
    }else{
    //they are not on the temp list.
    // add them to it.
    $this->bb_add_to_temp_list($this->_ip, 0, 1, 0);//if they're not on the list, then this is their first failed login.  Don't set a timestamp unless they've been blocked.
    }   
	}

public function bb_process_login_errors(){//called by WP when a website visitor makes a FAILED login attempt

	//resolve conflicts with other plugins.
	add_action('shutdown', array($this, 'bb_kill_scripts'), 1);

	//too much sleeping causes a fatal error max execution time exceeded - not called here because called later

    //clear their cookies
    wp_clear_auth_cookie();
    //log them out
    wp_logout();
	
    //the premise is that $this::bb_startup() should have already caught anyone on the permanent ban list...
    
	//so all we have to do here, is call the temporary ban test.
	$this->bb_test_for_temporary_ban();

     
}

//analyze a malformed cookie.
public function bb_check_malformed($cookie = '', $scheme = ''){

	//resolve conflicts with other plugins.
	add_action('shutdown', array($this, 'bb_kill_scripts'), 1);	

	if( is_admin() && $cookie == '' && $scheme == '' ){
	
		$this->_reason .= "Auth cookies were not properly set.  ";
	
		//this is a reasonable thing to do, once in a while.
		//but suspicious if done over and over.
		//so we log them.
		$this->bb_test_for_temporary_ban();
	
		if( !$this->is_login_page() ){//prevent infinite redirect loop...
			//Let them try to log in
			$uri = wp_login_url();
			wp_logout();
			wp_redirect($uri);
			exit();
			}
		}else{
			if($cookie != '' || $scheme != ''){
				$this->_reason .= "Header packet forgery!  Spoofed auth cookies.  Insta-ban.  ";
			
				$this->bb_add_to_ban_list();//calls block_the_brute
				}
		}
} 

public function bb_change_login_error_message(){//used to change WP's default error message, which supplies WAY too much information!
        $msg = $this->_message;
        
        if($msg != ''){
            return '<p class="error">' . $msg . '</p>';
        }
    
	return '<p class="error">The supplied credentials are incorrect.  Please check them <em>very</em> carefully before you try again.</p>';
	}

private function bb_convert_temp_to_perm(){//if they were temp blocked, but then logged in successfully
	//kick them out, and block them permanently.
	
    //clear their cookies
    wp_clear_auth_cookie();
    //log them out
    wp_logout();
    //destroy the session?    
	
            $this->bb_remove_from_temp_list();
            $this->bb_add_to_ban_list();//calls block_the_brute() and terminates execution
	
	exit();    
}

protected function bb_add_to_temp_list($ip, $blocks, $fails, $timestamp){
    
    $file = $this->_temp_block_list;
    
    $new_record = array($ip, $blocks, $fails, $timestamp);
    if (($handle = fopen($file, "ab")) !== FALSE) {    //the 'a' flag is key!
        fputcsv($handle, $new_record);
        fclose($handle);
    }else{
        
        die();//"system error"
        
    }
	if($this->_use_sleep){
		sleep(14);    
	}
	
}

protected function bb_update_temp_list($ip, $blocks, $fails, $timestamp){
    // all right, fine, I'm writing all the data to a temp file to avoid out of memory bounds issues, even though they're unlikely with a file this size.
    
	
	$file = $this->_temp_block_list;
	$ip = $this->_ip;
	$tempfile = $this->_dir_base . 'bruteblock-temp.csv'; 	
		
	// based on http://stackoverflow.com/questions/4072015/remove-line-from-csv-file
    $fptemp = fopen($tempfile, "a+");
    if (($handle = fopen($file, "r")) !== FALSE) {
        while (($data = fgetcsv($handle)) !== FALSE) {
		
            if ($ip != $data[0] ){//other records.
			
				fputcsv($fptemp, $data);
            }else{
                $new_data = array($ip, $blocks, $fails, $timestamp);
                fputcsv($fptemp, $new_data);
            }
        }
    }
    fclose($handle);
    fclose($fptemp);
	if(! unlink($file)){
		chown($file, 666);
		unlink($file);
	}
    if(! rename($tempfile, $file)){
		chown($tempfile, 666);
		rename($tempfile, $file);  
	}

	if($this->_use_sleep){
		sleep(19);
	}
	

}

protected function bb_remove_from_temp_list(){
    $file = $this->_temp_block_list;
    $ip = $this->_ip;
	$tempfile = $this->_dir_base . 'bruteblock-temp.csv'; 
    
// also based on http://stackoverflow.com/questions/4072015/remove-line-from-csv-file
    $fptemp = fopen($tempfile, "a+");
    if (($handle = fopen($file, "r")) !== FALSE) {
        while (($data = fgetcsv($handle)) !== FALSE) {
            if ($ip != $data[0] ){
				fputcsv($fptemp, $data);				
            }//no else statement: this way, the line is simply not included in the new copy of the file.
        }
    }
    fclose($handle);
    fclose($fptemp);
	
	if(! unlink($file)){
		chown($file, 666);
		unlink($file);
	}
    if(! rename($tempfile, $file)){
		chown($tempfile, 666);
		rename($tempfile, $file);  
	}    
    
}


public function bb_add_to_ban_list(){
	wp_clear_auth_cookie();
    wp_logout();	
	
	//resolve conflicts with other plugins.
	add_action('shutdown', array($this, 'bb_kill_scripts'), 1);	
	
    $ban_list = $this->_ban_list;//unfriendly addresses will be dynamically added to this list 
    $ip = $this->_ip . ',';//we now manually add the comma to our so-called comma delimited file...
    
    
    if(is_writeable($ban_list)){
        $handle = fopen($ban_list, "ab");

		//the ban list is now a csv file.  Not a txt file.
		//but we're NOT using fputcsv any more, because it automatically terminates each record with a newline
		//which breaks our test for identical IP matches.  must be no whitespace between the commas and the values.
	
		fwrite($handle, $ip);//this is the heart of the matter.
		fflush($handle);
		fclose($handle);
      
    }else{//can't write to ban list.  Just die.
		die();
	} 
	
	//notify the website administrator.
	//better plugins have an option to send the message to somebody other than the primary site admin.  
	//This is not one of those plugins.	
	if(function_exists('is_multisite') && is_multisite()){
		$to = get_site_option('admin_email');
	}else{
		$to = get_option('admin_email');
	}

	$subject = "A brute was blocked from " . $_SERVER['SERVER_NAME'];

	$message = $subject;
	$message .= " by the Brute Block plugin.

The attacker's IP address was added to the block list.  
In order to access your website again, this attacker will have to use a different IP address.
This may not stop the attack, but should slow down the attacker by forcing them to switch to a different proxy server.

If you believe this was a legitimate user who had trouble typing their password correctly,
you will have to delete the following address from the file permanent_ban.csv, located within the BruteBlock plugin folder:

Blocked IP
---------------------
" . $this->_ip . "


Blocked for: " . $this->_reason . "


Thank you for using Brute Block.  Have a secure day.";
	
	

	
	wp_mail($to, $subject, $message);

    $this->block_the_brute();//terminates.
}



    
}//end class definition
?>
