# postfix-blackwhitelist
Provides Postfix with spam blacklisting (and whitelisting) capabilities

# Postfix Setup
Right now I've only tested with postfix, may work elsewhere too.

1. Setup spam and whitelist aliases
  * Do this wherever your mail user aliases are defined (for me this was in an 'aliases' MySQL table)
  * Note this is not necessarily the /etc/postfix/aliases.db file (e.g. my installation first checks MySQL to see if a user/alias exists)
  * Add an entry so `spam@example.com` forwards to `spamparse@example.com`
  * Add an entry so `whitelist@example.com` forwards to `spamparse@example.com`
2. Setup script alias
  * Add the following line to `/etc/postfix/aliases`
    * `spamparse: "|/etc/postfix/mailscript/parse.py"` (or wherever you are placing this script)
3. Create necessary files (see Blacklist/Block/Stats config options)
  * Simply `touch /etc/spamassassin/90_myrules.cf` should be sufficient (also `chmod 0777` is necessary, because postfix executes with user nobody permissions, maybe there is a better way)
  * Repeat for each log/config file
