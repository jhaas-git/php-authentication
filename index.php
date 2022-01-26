<?php 
    if (isset($_GET['authenticationProcess'])) {
        include 'model/authenticationProcess.php';

        switch ($_GET['authenticationProcess']) {
            case 1: ;
            break;
        }
    } else {
        header('location: template/account.php');
    }
?>