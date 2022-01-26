<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="../design/authForm.css">
    <title>Account</title>
</head>
<body>
    <main>
        <section class="account-actions">
            <div class="account-actions-container">
                <div class="account-actions-body">
                    <?php if (isset($_GET['register'])) {
                    echo '<p class="action-title">Sign up</p>
                    <form action="../index.php?authenticationProcess=1" method="post">
                    <div class="form-row" id="double-input">
                        <div class="input-container"><label>First name</label><input type="text" name="first_name"></div>
                        <div class="input-container"><label>Last name</label><input type="text" name="last_name"></div>
                    </div>
                    <div class="form-row">
                        <div class="input-container"><label>Mail address</label><input type="text" name="mail_address"></div>
                    </div>
                    <div class="form-row" id="double-input">
                        <div class="input-container"><label>Password</label><input type="password" name="password"></div>
                        <div class="input-container"><label>Confirm password</label><input type="password" name="confirm_password"></div>
                    </div>
                    <button class="submitBtn">Create account</button>
                    </form>
                    <a href="account.php" class="action-link">Already have an account? Sign in here.</a>';
                    } else {
                    echo '<p class="action-title">Sign in</p>
                    <form action="../index.php?authenticationProcess=2" method="post">
                    <div class="form-row">
                        <div class="input-container"><label>Mail address</label><input type="text" name="mail_address"></div>
                    </div>
                    <div class="form-row">
                        <div class="input-container"><label>Password</label><input type="password" name="password"></div>
                    </div>
                    <button class="submitBtn">Authenticate</button>
                    </form>
                    <a href="account.php?register" class="action-link">Not yet registered? Sign up here.</a>';
                    } ?>
                </div>
            </div>
        </section>
    </main>
</body>
</html>