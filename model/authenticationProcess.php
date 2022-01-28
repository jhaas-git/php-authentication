<?php 
    function registerAccount() {
        require 'model/pdo/config.php';

        // Make sure the post values aren't empty.
        if (!empty($_POST['first_name']) && !empty($_POST['last_name']) && !empty($_POST['mail_address']) && !empty($_POST['password']) && !empty($_POST['confirm_password'])) {
            // When post values are filled, check if the password is equal to the password confirmation.
            if (($_POST['password']) == ($_POST['confirm_password'])) {
                // When the password and confirmation match, assign the post values to a variable.
                $first = $_POST['first_name'];
                $last = $_POST['last_name'];
                $mail = $_POST['mail_address'];
                $pass = $_POST['password']; 
                $hash = hash('sha256', $pass); // Password will be hashed.

                // Prevent duplicates by checking if the user already exists.
                $fetchExistingAccount = 'SELECT * FROM account WHERE sMailAddress = :post_mail';
                $stmt = $pdo->prepare($fetchExistingAccount);
                $stmt->execute([
                    ':post_mail' => $mail
                ]);
                // Assigning rowCount result to a readable variable.
                $existingAccount = $stmt->rowCount();

                if ($existingAccount > 0) { 
                    // If more than zero results are found,
                    // redirect to register page. error message sent through the GET.
                    header('location: template/account.php?register=alreadyExists');
                } elseif ($existingAccount == 0) {
                    // When no results are found, insert post values into database.
                    $insertAccount = 'INSERT INTO account (sFirstname, sLastname, sMailaddress, sPassword)
                    VALUES (:post_first, :post_last, :post_mail, :post_pass)';
                    $stmt = $pdo->prepare($insertAccount);
                    $stmt->execute([
                        ':post_first' => $first,
                        ':post_last' => $last,
                        ':post_mail' => $mail,
                        ':post_pass' => $hash
                    ]);
                    header('location: template/account.php?registrationSuccessfull'); // Redirect to login page, success message sent through the GET.
                }
            } else {
                header('location: template/account.php?register=matchingPassword'); // Redirect to register page, error message sent through the GET.
            }
        } else {
            header('location: template/account.php?register=missingFields'); // Redirect to register page, error message sent through the GET.
        }
    }

    function authenticateAccount() {

    }

    function disconnectAccount() {

    }
    
    // Checking whether a session is started or not.
    function is_session_started() {
        if (php_sapi_name() !== 'cli') {
            if (version_compare(phpversion(), '5.4.0', '>=')) {
                return session_status() === PHP_SESSION_ACTIVE ? TRUE : FALSE;
            } else {
                return session_id() === '' ? FALSE : TRUE;
            }
        }
        return FALSE;
    }
?>