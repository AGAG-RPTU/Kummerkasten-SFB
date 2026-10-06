#!/bin/sh
# Stands in for sendmail in the tests and in local development: appends the
# arguments PHP passed and the mail itself to the file $KK_MAIL_LOG names.
#   KK_MAIL_LOG=... php -d sendmail_path=$PWD/tools/dev-sendmail.sh ...
echo "Sendmail-Args: $*" >> "$KK_MAIL_LOG"
cat >> "$KK_MAIL_LOG"
