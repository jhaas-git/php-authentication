<?php 
    if (isset($_GET['authenticationProcess'])) {
        include 'model/authenticationProcess.php';

        switch ($_GET['authenticationProcess']) {
            case 1: registerAccount();
            break;
            case 2: authenticateAccount();
            break;
            case 3: disconnectAccount();
            break;
        }
    } else {
        header('location: template/account.php');
    }
?>