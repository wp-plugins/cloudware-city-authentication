=== Cloudware City Authentication ===
Contributors: cloudwarecity
Donate link: none
Tags: authentication, register, subscription, login, membership, restrict, access, cms
Requires at least: 3.0
Tested up to: 3.1
Stable tag: trunk

A plugin for authentication/authorisation using Cloudware City for subscription access to a Wordpress installation.

== Description ==

This plugin allows the use of the external Cloudware City authentication API to supplement the default authentication of users within a Wordpress installation. Users are authenticated using the API then added to the local Wordpress database based on the values in the plugin settings. This means existing user accounts can be used if necessary and local admin users can still be used.

When used in conjunction with another plugin (e.g. Page Restrict, Members Only etc) that restricts access to logged in users, this plugin allows a subscription membership site to be set up with ease.

== Installation ==

1. Upload the 'cloudwarecity-auth' authentication folder to the '/wp-content/plugins/' directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Review the 'Cloudware City' settings in the Wordpress settings menu, and fill out the details of your Cloudware City Vendor ID, API and Product IDs. Be careful when assigning the role - by default this is 'Subscriber', but you may select whatever role you require subscribed users to have. It will update (along with the users details) every time the user logs in.

== Frequently Asked Questions ==

= How can I set up the authentication? =
All you need is to set up an account at Cloudware City, define your Vendor and Product details, and then insert the parameters into the authentication settings page. Any user that has subscribed to your product at Cloudware City will be able to authenticate using their login details, and be authorised according to the length of subscription.

= How does this plugin authenticate users? =
When a user submits their username and password, the plugin authenticates via the Cloudware City API by encrypting the password with a one-way hash, building the message including the vendor and product ids and finally "signing" the message with the API key to ensure integrity. The resulting authentication process takes place at Cloudware City and if the authentication succeeds, the user is granted access.

= What errors can be received? =
If you receive an error 'Malformed authentication - invalid key' please ensure your API key and Vendor ID in Settings match that on Cloudware City, and that you are authenticating against the correct server (live or Demo via checkbox).
If you receive an error 'Malformed authentication - missing id' please ensure you have entered the correct Product ID as listed on Cloudware City.

Active Cloudware City users that attempt log in may receive one of two errors (other than invalid password) - "Subscription has expired" (for users with expired subscriptions), and "Subscription is required" (for users that have not yet subscribed).

= If I disable the plugin, how will I log in? =
The plugin only creates and updates existing accounts, it doesn't alter any passwords, therefore you can still authenticate using your admin username and password. In addition, user accounts created or updated via Cloudware City authentication will continue to function (although no access control or subscription expiration facilities will be available once the plugin is disabled).

= My question isn't here, what next?! =
If you have any questions or comments please get in touch via the contact details at http://cloudwarecity.com/vendor/downloads

== Screenshots ==

1. The settings page
2. The login screen

== Changelog ==

= 1.0 =
First Release

== Upgrade Notice ==

= 1.0 =
Latest Release - No upgrades available
