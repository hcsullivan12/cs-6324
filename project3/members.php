<?php
	include('connect.php');
        include('util.php');

        // Connect to database
	connect();

        // Get session
        start_session();
	
	//if the login form is submitted 
	if (isset($_POST['submit'])) {
		
		$_POST['username'] = trim($_POST['username']);
		if(!$_POST['username'] | !$_POST['password']) {
			die('<p>You did not fill in a required field.
			Please go back and try again!</p>');
		}

		$check = mysql_query("SELECT * FROM users WHERE username = '".mysql_real_escape_string($_POST['username'])."'")or die(mysql_error());
		
 		//Gives error if user already exist
 		$check2 = mysql_num_rows($check);
		if ($check2 == 0) {
			die("<p>Sorry, user name does not exisits.</p>");

		} else {
                    $row = mysql_fetch_assoc($check);

                    if (password_verify($_POST['password'], $row['pass'])) {
                        log_in_session($_POST['username']);
			header("Location: members.php");

                    } else {
                        die('<p>Incorrect password!</p>');
                    }
		}
	}
		?>  
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>hackme</title>
<link href="style.css" rel="stylesheet" type="text/css" media="screen" />
<?php
	include('header.php');
?>
<div class="post">
	<div class="post-bgtop">
		<div class="post-bgbtm">
        <h2 class = "title">hackme bulletin board</h2>
        	<?php

            if(!isset($_SESSION['LOGGED_IN_USER'])){
				 die('Why are you not logged in?!');
			}else
			{
				print("<p>Logged in as <a>$_SESSION[LOGGED_IN_USER]</a></p>");
			}
			?>
        </div>
    </div>
</div>

<?php
	$threads = mysql_query("SELECT * FROM threads ORDER BY date DESC")or die(mysql_error());
	while($thisthread = mysql_fetch_array( $threads )){
?>
	<div class="post">
	<div class="post-bgtop">
	<div class="post-bgbtm">
		<h2 class="title"><a href="show.php?pid=<?php echo $thisthread['id'] ?>"><?php echo htmlspecialchars($thisthread['title'], ENT_QUOTES, 'UTF-8')?></a></h2>
							<p class="meta"><span class="date"> <?php echo date('l, d F, Y',$thisthread[date]) ?> - Posted by <a href="#"><?php echo htmlspecialchars($thisthread[username], ENT_QUOTES, 'UTF-8') ?> </a></p>

	</div>
	</div>
	</div> 

<?php
}
	include('footer.php');
?>
</body>
</html>
