BruteBlock
==========

A blunt instrument for blocking brute force attacks on a WordPress installation.  
-Insta-ban login attempts from outside a permitted geographical region.
-Insta-ban login attempts via forged auth cookies.
-Track login failures, and ban users who exceeded the permitted maximum.
-Banned visitors are denied all access to the website
-All IP addresses on the StopForumSpam list are denied all access to the website.


This concept (IP-based blocking) is already deprecated in favor of .htaccess allow rules for wp-login.php, but hey!  


BruteBlock.php is the core file for a WordPress plugin.  The actual plugin includes at least two additional files:

bannedips.csv - current list of bad actors downloaded from StopForumSpam.com

MaxMind-US-IPs-min.csv - a two-column csv file with "from" and "to" long IP network ranges 
defining the allowed geographical region (in this case, the United States).  I gleaned mine from GeoLite 
country data downloaded from MaxMind.com.


When an attacker's IP address is blocked, BruteBlock denies them access to any page of your website.  
If the visitor is on the StopForumSpam list, or if they have gotten blocked for doing something naughty, 
then they will not be able to see any pages, much less try to brute force your login or submit spam comments.  
(Unless they have a botnet with 90,000 computers.... because then they could just rapidly switch between a 
huge number of IP addresses and bombard your site...)  
