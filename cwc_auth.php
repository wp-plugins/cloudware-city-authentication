<?php
/*
	Plugin Name: Cloudware City Authentication
	Plugin URI: http://cloudwarecity.com/vendor/downloads
	Description: Used to externally authenticate and authorise WP users using Cloudware City
	Version: 1.01
	Author: Keith Hall
	Author URI: http://cloudwarecity.com/vendor/aboutapi
	License: GNU General Public License (GPL) version 2

	Copyright 2010  Keith Hall  (email : cwc@cloudwarehosting.com)

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License, version 2, as
	published by the Free Software Foundation.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1335  USA

	Thanks to Matthew Kellett for his Soap Auth which was a great help in
	developing this plug-in.
*/


/**
 * Cloudware_Auth
 *
 * A class to authenticate Wordpress users using Cloudware City
 *
 * @author Keith Hall
 * @version 1.01
 * @todo Add the ability to handle multiple product IDs
 */
class Cloudware_Auth
{

	/**
	 * Cloudware_Auth::getOptions()
	 *
	 * This function sets up all of the options for the th class i.e. generates
	 * the options array, collects the current system roles for permission mappings and
	 * registers these options with the system
	 *
	 * @return void
	 */
	function getOptions()
	{
		$options = get_option('cwc_auth_options');
		if (!is_array($options)) {
			$options['cwc_vendorid'] 	= '';
			$options['cwc_apikey'] 		= '';
			$options['role_mapping']	= 'Subscriber';
			$options['cwc_prodid'] 		= '';
			$options['test_mode']		= '';
			$options['demo_mode']		= '';
			$options['show_link']		= 'on';

			#add role options
			global $wp_roles;
			$roles = $wp_roles->get_names();
			foreach ($roles as $name => $display){
				$options['role_'.$name]	= '';
			}

			update_option('cwc_auth_options', $options);
		}
		return $options;
	}

	/**
	 * Cloudware_Auth::updateOptions()
	 *
	 * This function will update the available options for the the class.
	 * All parameters passes through from the $_POST array are cleansed before
	 * being assigned to the relevant options. 
	 *
	 * @return void
	 */
	function updateOptions()
	{
		if(isset($_POST['save_cwc_settings']))
		{
			$options = Cloudware_Auth::getOptions();

			$options['cwc_vendorid'] 	= stripslashes($_POST['cwc_vendorid']);
			$options['cwc_apikey'] 		= stripslashes($_POST['cwc_apikey']);
			$options['role_mapping'] 	= stripslashes($_POST['role_mapping']);
			$options['cwc_prodid'] 		= stripslashes($_POST['cwc_prodid']);
			$options['test_mode'] 		= stripslashes($_POST['test_mode']);
			$options['demo_mode'] 		= stripslashes($_POST['demo_mode']);
			$options['show_link']		= stripslashes($_POST['show_link']);

			update_option('cwc_auth_options', $options);
		}
		else
		{
			Cloudware_Auth::getOptions();
		}

		#add menu
		Cloudware_Auth::cwc_auth_add_menu();

	}

	/**
	 * Cloudware_Auth::cwc_auth_add_menu()
	 *
	 * Creates the default menu option once the plugin has been activated. 
	 *
	 * @return void
	 */
	function cwc_auth_add_menu()
	{
		# add the menu to the main options section
		add_options_page(
			__('Cloudware City', 'Cloudware_Auth'),
			__('Cloudware City', 'Cloudware_Auth'),
			'manage_options', basename(__FILE__),
			array('Cloudware_Auth', 'cwc_auth_display_options')
		);
		add_filter("plugin_action_links_".plugin_basename(__FILE__) , array('Cloudware_Auth', 'cwc_filter_plugin_actions'));
	}

	/**
	 * Cloudware_Auth::cwc_filter_plugin_actions()
	 *
	 * Creates the settings link in Plugins once activated. 
	 *
	 * @return void
	 */

	function cwc_filter_plugin_actions($links)
	{
        $settings_link = '<a href="options-general.php?page=cwc_auth">' . __( 'Settings' ) . '</a>';
        array_unshift($links, $settings_link);
        return $links;
	}

	/**
	 * Cloudware_Auth::cwc_auth_display_options()
	 *
	 * This function builds the main admin interface for the plugin. It basically
	 * builds a form and adds the options to it in the relevant sections.
	 *
	 * @return void
	 */
	function cwc_auth_display_options()
	{
		# initialise global objects
		global $wp_roles;
		$roles = $wp_roles->get_names();
		$options = Cloudware_Auth::getOptions();
		?>
		<div class="wrap">
			<h2>Cloudware City Authentication Settings</h2>
			<form method="post" action="" id="cwc_auth_settings_form">
			<?php settings_fields('cwc_auth_options'); ?>
			    <h3>Vendor specific details</h3>
				<p>The details as shown on the Vendor Registration Details page on Cloudware City (<a href="http://cloudwarecity.com/vendor/vendorregister">http://cloudwarecity.com/vendor/vendorregister</a>)</p>
				<table class="form-table">
                    <tbody>
                    <tr valign="top">
                        <th scope="row">
                            <label for="cwc_vendorid">Vendor ID</label>
                        </th>
                        <td>
							<input type="text" size="6" name="cwc_vendorid" id="cwc_vendorid" value="<?php echo $options['cwc_vendorid']; ?>" />
							<span class="description">your 'Auth site ID'</span>
						</td>
					</tr>
                    <tr valign="top">
                        <th scope="row">
							<label for="cwc_apikey">Auth API Key</label>
                        </th>
                        <td>
                        	<input type="text" size="64" name="cwc_apikey" id="cwc_apikey" value="<?php echo $options['cwc_apikey']; ?>" />
							<span class="description">your 'Auth API key'</span>
						</td>
					</tr>
                    </tbody>
				</table>
				<h3>Product specific details</h3>
				<p>The ID of the product as shown on the Product Listing page on Cloudware City (<a href="http://cloudwarecity.com/vendor/productlist">http://cloudwarecity.com/vendor/productlist</a>)</p>
				<table class="form-table">
                    <tbody>
                    <tr valign="top">
                        <th scope="row">
							<label for="cwc_prodid">Product ID</label>
                        </th>
                        <td>
							<input type="text" name="cwc_prodid" id="cwc_prodid" value="<?php echo $options['cwc_prodid']; ?>" />
							<span class="description">your 'API Product ID'</span>
						</td>
					</tr>
                    </tbody>
				</table>
                <h3>Other options</h3>
                <p>The options below allow you to select which Role users are given when logging in and two testing options. Users details including role are set upon each login. The Test mode alters the authentication so that only the Vendor's Cloudware City user id and password will work (disables all other user account access), and the Demo server auth switches the authentication platform to the Demo Public Sandbox system, if you are wanting to test on there.</p>
				<table class="form-table">
                    <tbody>
                    <tr valign="top">
                        <th scope="row">
							<label for="role_mapping">Role mapping</label>
                        </th>
                        <td>
							<select name="role_mapping" id="role_mapping">
		<?php
		foreach ($roles as $name => $display)
		{ 
			echo '<option value="'.$name.'"'.($options['role_mapping']==$name?" selected":"").'>'.$display.'</option>';
		}
		?>
							</select>
							<span class="description">Users are mapped onto this role upon login</span>
						</td>
					</tr>
                    <tr valign="top">
                        <th scope="row">Options</th>
						<td>
                        	<fieldset>
							<p>
								<input type="checkbox" name="test_mode" id="test_mode" <?php echo ($options['test_mode']=='on'?" checked":""); ?> />
                            	<label for="test_mode">Test mode</label>
								<span class="description"> Tick this if testing before product is live (enables Vendor's credentials to auth)</span>
                            <br />
								<input type="checkbox" name="demo_mode" id="demo_mode" <?php echo ($options['demo_mode']=='on'?" checked":""); ?> />
								<label for="demo_mode">Demo server auth</label>
								<span class="description"> Tick this if testing against the Cloudware City Demo sandbox platform</span>
                            <br />
								<input type="checkbox" name="show_link" id="show_link" <?php echo ($options['show_link']=='on'?" checked":""); ?> />
								<label for="show_link">Show subscription link</label>
								<span class="description"> Tick this to provide an easy subscription link to users on the login screen</span>
                            </p>
                            </fieldset>
						</td>
					</tr>
				</tbody>
                </table>
				<p class="submit">
					<input type="submit" name="save_cwc_settings" id="sumbit" value="Save Changes" />
				</p>
			</form>
		</div>
		<?php
	}

	/**
	 * Cloudware_Auth::cwc_auth_check_login()
	 *
	 * This is the main authentication function of the plugin. Given both the username and password it will
	 * make use of the options set to authenticate against Cloudware City either live or demo systems.
	 * If a user is authenticated and already exists in the system then their details will be updated, otherwise
	 * it will generate a new user and set up their permissions based on the role mapping.
	 *
	 * @param string $username
	 * @param string $password
	 * @return void
	 */
	function cwc_auth_check_login($username, $password)
	{
		require_once(ABSPATH.'wp-includes/registration.php');

		$options = Cloudware_Auth::getOptions();
		$cwc_vendorid = ($options['cwc_vendorid'] != "") ? $options['cwc_vendorid'] : null;
		$cwc_prodid = ($options['cwc_prodid'] != "") ? $options['cwc_prodid'] : null;
		$cwc_apikey = ($options['cwc_apikey'] != "") ? $options['cwc_apikey'] : null;
		$role_mapping = ($options['role_mapping'] != "") ? $options['role_mapping'] : null;
		$test_mode = ($options['test_mode'] != "") ? 1 : 0;
		$demo_mode = ($options['demo_mode'] != "") ? 1 : 0;

		if (!is_null($username) && !is_null($cwc_vendorid) && !is_null($cwc_prodid))
		{
			// calc pw hash
			$hash = md5($username.$password);
			$skey = $sites[$vendor]['skey'];
		
			// calc msg hash
			$key = sha1($cwc_vendorid.$cwc_prodid.$username.$hash.$cwc_apikey);
			
			$msg = "sid=$cwc_vendorid&pid=$cwc_prodid&us=$username&pw=$hash&key=$key" . ($test_mode?"&test=1":"");

			if(!function_exists(curl_init))
			{
				$message = "Curl not found on this system, please install. ";
			}
			else
			{
				$curlSession = curl_init();
	
				if($demo_mode)
					$baseurl = "https://demo.cloudwarecity.com";
				else
					$baseurl = "https://auth.cloudwarecity.com";
			
				curl_setopt ($curlSession, CURLOPT_URL, $baseurl."/api/auth?$msg");
				curl_setopt ($curlSession, CURLOPT_HEADER, 0);
				curl_setopt ($curlSession, CURLOPT_POST, 0);
			//	curl_setopt ($curlSession, CURLOPT_POSTFIELDS, $msg);
				curl_setopt($curlSession, CURLOPT_FOLLOWLOCATION,1);
				curl_setopt($curlSession, CURLOPT_RETURNTRANSFER,1); 
				curl_setopt($curlSession, CURLOPT_TIMEOUT,30); 
				curl_setopt($curlSession, CURLOPT_DNS_USE_GLOBAL_CACHE, FALSE);
				curl_setopt($curlSession, CURLOPT_SSL_VERIFYPEER, FALSE);
				curl_setopt($curlSession, CURLOPT_SSL_VERIFYHOST, 1);
	
				$rawresponse = curl_exec($curlSession);
			
				if (curl_error($curlSession))
				{
					$rawresponse = curl_exec($curlSession); // abnormal - try once more
					if (curl_error($curlSession))
						$message = "ERROR: ".curl_error($curlSession);
				}
				curl_close ($curlSession);
			
				$prodlist = array();
				$resp = "";
	
				$authenticated = false;
				if(!function_exists(simplexml_load_string))
					$message .= "SimpleXML not found on this system, please install. ";

//				error_log($rawresponse);

				if (@simplexml_load_string($rawresponse))
				{
					$xml = new SimpleXMLElement($rawresponse);
			
					if($xml->getName() == "cwcapi")		
					{
//						$username = $xml->username;
						$firstname = $xml->firstname;
						$lastname = $xml->lastname;
						$email = $xml->email;
						$userid = $xml->userid;
						$result = $xml->result;
						$products = $xml->products;
						$authcode = $xml->authcode;
//						foreach($products->children() as $subprod)
//						{
//							$attr = $subprod->attributes();
//							$id = (string)$attr->id;
//							$prodlist[$id] = $subprod->expiresecs;
//						}
					}
					switch($result)
					{
						case "INVALID":
							$message = 'Incorrect username/password';
							break;
						case "VALID"; // won't see for single product auth
							$message = "Malformed authentication - missing id";
							break;
						case "MALFORMED";
							$message = 'Malformed authentication - invalid key';
							break;
						case "NOTAUTH";
							$message = 'Subscription is required';
							break;
						case "EXPIRED";
							$username = NULL; // explicitly deny login always if expired
							$message = "Subscription has expired";
							break;
						case "OK";
							$authenticated = true;
							break;
					}
//					$resp .= "<strong>Username:</strong> $username<br><strong>User ID:</strong> $userid<br><strong>Authorisation number:</strong> $authcode<br><br>";
//					$resp .= "User product subscriptions count for this vendor: ".count($prodlist)."<br><br><strong>Individual product data:</strong><br>";
//					foreach($prodlist as $p=>$e)
//					{
//						$resp .= "Product $p expires: " . $e . " seconds" . ($e<0 ? " (expired)" : " (active)") ."<br>";
//					}
				}
			}

//			error_log("auth: $username, $authenticated, map $role_mapping");
			
			if($authenticated)
			{
				# disable registration for the current user:
				remove_action('user_register', array('Cloudware_Auth', 'disable_function'));
				# user has been authenticated so set up the required fields in the WP database
				$userdetails = $response[$options['auth_user_dets']];
				$userarray['user_login'] 	= $username;
				$userarray['user_pass'] 	= $password;
				$userarray['first_name'] 	= $firstname;
				$userarray['last_name'] 	= $lastname;
				$userarray['user_email'] 	= $email;
				$userarray['display_name'] 	= $username;
		
				#check if the user exists in the system, if they do then update it
				if($id = username_exists($username))
				{
					$userarray['ID'] = $id;
					wp_update_user($userarray);
				}
				else
				{
					#otherwise create the user
					$user_id = wp_insert_user($userarray);
					$userarray['ID'] = $user_id;
				}
				
				if (isset($userarray['ID']) && !is_null($role_mapping))
				{
					$userobj = new WP_User($userarray['ID']);
					$userobj->set_role($role_mapping);
//					error_log("Capability for ".$username." (".$userarray['ID'].") is: " . var_export($userobj->roles, true));
				}
			}
			else
			{
				# if failed auth and username doesn't exist in WP database, report the Cloudware City authentication failure alone and deny login (set username to NULL)...
				# otherwise let WordPress handle the authentication (allows WP accounts to be used to override Cloudware City authentication failures except for expirations)
				global $error_msg;
				$error_msg = $message;
				if(!username_exists($username)) 
				{
					$username = NULL;
					global $error_type;
					$error_type = "noauth";
				}
			}
		}
		else
		{
			global $error_msg;
			$error_msg = "The authentication settings could not be found, please contact an administrator to update these so you can log in";
			global $error_type;
			$error_type = "nocwc";
		}
	}


	/**
	 * Cloudware_Auth::cwc_auth_warning()
	 *
	 * Prints out a the message to be displayed on the login screen.
	 *
	 * @return void
	 */
	function cwc_auth_warning()
	{
		$opts = Cloudware_Auth::getOptions();
		$cwc_prodid = ($opts['cwc_prodid'] != "") ? $opts['cwc_prodid'] : null;
		$show_link = ($opts['show_link'] != "") ? 1 : 0;
		echo "<div class=\"message\">Please enter your Cloudware City username and password below.";
		if($show_link)
			echo "<br><br>If you don't have a username and password, please <a href=\"http://cloudwarecity.com/getprodinfo?q=1&p=" . $cwc_prodid . "\">Subscribe</a> to this site via Cloudware City.";
		echo "</div>";
	}

	/**
	 * Cloudware_Auth::cwc_errors()
	 *
	 * A function for building the error messages shown typically on login
	 *
	 * @return string Returns the error message from the thentication call
	 */
	function cwc_errors()
	{
		global $error;
		global $error_type;
		global $error_msg;

		if ($error != "") {
			$error = "<br /><br />" . $error;
		}
		if ($error_msg != "")
		{
			$error_msg = "<br><br><b>" . $error_msg . "</b>";
		}

		switch($error_type)
		{
			case 'noauth':
				$error_out = "There was an error authenticating your details.".$error_msg;
				break;
			case 'cwc':
				$error_out = $error_msg;
				break;
			case 'nocwc':
				$error_out = $error_msg;
				break;
			default:
				$error_out = "There was an error, contact an admin.".$error_msg . $error;
				break;
		} // switch

		return $error_out;
	}

	/**
	 * Cloudware_Auth::cwc_warning()
	 *
	 * This function outputs a warning to the main user profile section to inform
	 * the users that changes to personal information will be overwritten if changed
	 * the next time they log in
	 *
	 * @return void
	 */
	function cwc_warning()
	{
		echo '<strong style="color:red;">Changes made to first name/last name/e-mail below may not be preserved when you login again. You have to change your personal information on your <a href="https://cloudwarecity.com/userprofile">Cloudware City user profile</a>.</strong>';
	}

	/**
	 * Cloudware_Auth::cwc_show_password_fields()
	 *
	 * Disables the password reset option in WP when this plugin is enabled because
	 * this should be handled by the Cloudware City system and not the wordpress system
	 * v1.01 - Enables password field for admin users.
	 *
	 * @return
	 */
	function cwc_show_password_fields()
	{
		global $wp_roles;
		if(current_user_can('edit_users'))
			return 1;
		else
			return 0;
	}

	/**
	 * Cloudware_Auth::disable_function_register()
	 *
	 * This functions will disable the default registration for the system when
	 * the the plugin is enabled
	 *
	 * @return void
	 */
	function disable_function_register()
	{
		$errors = new WP_Error();
		$errors->add(
			'registerdisabled',
			__('User registration is not available from this site, so you can\'t create an account or retrieve your password from here. See the message above.')
		);
		?></form><br /><div id="login_error">User registration is not available from this site, so you can't create an account or retrieve your password from here. See the message above.</div>
				<p id="backtoblog"><a href="<?php bloginfo('url'); ?>/" title="<?php _e('Are you lost?') ?>"><?php printf(__('&larr; Back to %s'), get_bloginfo('title', 'display' )); ?></a></p>
			<?php
		exit();
	}

	/**
	 * Cloudware_Auth::disable_function()
	 *
	 * The main error function to be used when a user tries to
	 * register or uses the forgotten password form
	 *
	 * @return void
	 */
	function disable_function()
	{
		$errors = new WP_Error();
		$errors->add(
			'registerdisabled',
			__('User registration is not available from this site, so you can\'t create an account or retrieve your password from here. See the message above.')
		);
		login_header(__('Log In'), '', $errors);
		?>
			<p id="backtoblog"><a href="<?php bloginfo('url'); ?>/" title="<?php _e('Are you lost?') ?>"><?php printf(__('&larr; Back to %s'), get_bloginfo('title', 'display' )); ?></a></p>
			<?php
		exit();
	}
}

/**
 * Register the functions form the Cloudware_Auth class within the
 * relevant sections of the system
 */
if(is_admin())
{
	add_action('admin_menu', array('Cloudware_Auth', 'updateOptions'));
}
add_action('wp_authenticate', array('Cloudware_Auth', 'cwc_auth_check_login'), 1, 2);
add_action('lost_password', array('Cloudware_Auth', 'disable_function'));
add_action('user_register', array('Cloudware_Auth', 'disable_function'));
add_action('wordp', array('Cloudware_Auth', 'disable_function_register'));
add_action('retrieve_password', array('Cloudware_Auth', 'disable_function'));
add_action('password_reset', array('Cloudware_Auth', 'disable_function'));
add_action('profile_personal_options', array('Cloudware_Auth', 'cwc_warning'));
add_filter('login_errors', array('Cloudware_Auth', 'cwc_errors'));
add_filter('show_password_fields', array('Cloudware_Auth', 'cwc_show_password_fields'));
add_filter('login_message', array('Cloudware_Auth', 'cwc_auth_warning'));
