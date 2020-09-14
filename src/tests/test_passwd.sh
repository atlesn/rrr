#!/bin/sh

TEST_PASSWD=../rrr_passwd
TEST_AUTH=../rrr_auth

TEST_PASSWD_FILE=.rrr_test.passwd

TEST_PASSWD_USERNAME=rrr
TEST_PASSWD_PASSWORD=rrr
TEST_PASSWD_PASSWORD_INCORRECT=rr
TEST_PASSWD_PERMISSION=mqtt

TEST_ARGS="$TEST_PASSWD_FILE $TEST_PASSWD_USERNAME -d 1"

msg () {
	echo ""
	echo -n "--- "
	echo $1
}

msg "Unlinking password file"
rm -vf $TEST_PASSWD_FILE || true

msg "Creating user $TEST_PASSWD_USERNAME in file $TEST_PASSWD_FILE..."
$TEST_PASSWD $TEST_ARGS -c -P $TEST_PASSWD_PASSWORD || exit 1

msg "Authenticating user $TEST_PASSWD_USERNAME..."
echo -n $TEST_PASSWD_PASSWORD | $TEST_AUTH $TEST_ARGS -s || exit 1

msg "Authenticating user $TEST_PASSWD_USERNAME with wrong password..."
echo -n $TEST_PASSWD_PASSWORD_INCORRECT | $TEST_AUTH $TEST_ARGS -s && exit 1

msg "Authenticating user $TEST_PASSWD_USERNAME with no password..."
echo -n "" | $TEST_AUTH $TEST_ARGS -s && exit 1

msg "Adding permission $TEST_PASSWD_PERMISSION to user $TEST_PASSWD_USERMAME..."
$TEST_PASSWD $TEST_ARGS -p $TEST_PASSWD_PERMISSION

msg "Authenticating user $TEST_PASSWD_USERNAME with wrong permission..."
echo -n $TEST_PASSWD_PASSWORD | $TEST_AUTH $TEST_ARGS -s -p "wrong_permission" && exit 1

msg "Authenticating user $TEST_PASSWD_USERNAME with empty permission..."
echo -n $TEST_PASSWD_PASSWORD | $TEST_AUTH $TEST_ARGS -s -p "" && exit 1

msg "Authenticating user $TEST_PASSWD_USERNAME with correct permission..."
echo -n $TEST_PASSWD_PASSWORD | $TEST_AUTH $TEST_ARGS -s -p $TEST_PASSWD_PERMISSION || exit 1

msg "Setting empty password for $TEST_PASSWD_USERNAME..."
$TEST_PASSWD $TEST_ARGS -P ""

msg "Authenticating user $TEST_PASSWD_USERNAME which is now disabled..."
echo -n $TEST_PASSWD_PASSWORD | $TEST_AUTH $TEST_ARGS -s && exit 1

exit 0
