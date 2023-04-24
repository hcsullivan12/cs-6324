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

?>
