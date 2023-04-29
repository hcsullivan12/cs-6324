<?php

    function get_secure_password($password) {
        $options = [
            'cost' => 12,
        ];
        return password_hash($password, PASSWORD_BCRYPT, $options);
    }

    function debug_to_console($data) {
        $output = $data;
        if (is_array($output)) {
            $output = implode(',', $output);
        }
        echo "<script>console.log('DEBUG: " . $output . "' );</script>";
    }

    function start_session() {
        session_start([
            'cookie_lifetime' => 0,
            'use_only_cookies' => 1,
            'use_strict_mode' => 1,
            'cookie_httponly' => 1
        ]);

        
        $sessionTimeout  = 300;
        $activityTimeout = 600;

        if (isset($_SESSION['LAST_ACTIVITY']) && (time() - $_SESSION['LAST_ACTIVITY'] > $activityTimeout)) {
            session_unset();
            session_destroy();
            header("Location: index.php"); 
            exit;

        } else {
            $_SESSION['LAST_ACTIVITY'] = time();

            // Regenerate sessionID
            if (!isset($_SESSION['CREATED'])) {
                $_SESSION['CREATED'] = time();

            } else if (time() - $_SESSION['CREATED'] > $sessionTimeout) {
                session_regenerate_id(true);
                $_SESSION['CREATED'] = time();
            }
        }
    }

    function log_in_session($username) {
        $_SESSION['LOGGED_IN_USER'] = $username;
        $_SESSION['LAST_ACTIVITY'] = time();
    }

?>
