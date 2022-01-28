<?php
    include '../model/pdo/config.php';
    include '../model/authenticationProcess.php';

    if (is_session_started() === FALSE) session_start();
    if (!isset($_SESSION['signedin'])) {
        header('location: account.php');
        exit;
    }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $_SESSION['fname'] ?>'s profile</title>
</head>
<body>
    Welcome back, <?php echo $_SESSION['fname'] ?>.
</body>
</html>