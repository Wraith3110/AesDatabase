<?php
// Database credentials
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "account_manager";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Function to decrypt passwords
function decrypt_password($encrypted_password, $key) {
    return openssl_decrypt($encrypted_password, 'aes-256-cbc', $key, 0, '1234567890123456');
}

$application_name = "";
$encryption_key = "";
$account_info = [];
$auth_error = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $application_name = $_POST['application_name'];
    $encryption_key = $_POST['encryption_key'];

    // Authenticate user
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
    $stmt->bind_param("ss", $username, $password);
    $stmt->execute();
    $user_result = $stmt->get_result();

    if ($user_result->num_rows == 1) {
        // User authenticated, proceed to retrieve account information
        $stmt = $conn->prepare("SELECT account_name, password_hash FROM accounts WHERE application_name = ?");
        $stmt->bind_param("s", $application_name);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            while($row = $result->fetch_assoc()) {
                $row['password_hash'] = decrypt_password($row['password_hash'], $encryption_key);
                $account_info[] = $row;
            }
        } else {
            echo "No account found for the specified application name.";
        }
    } else {
        $auth_error = "Invalid username or password.";
    }

    // Close the statement
    $stmt->close();
}

$conn->close();
?>

<!DOCTYPE html>
<html>
<head>
    <title>Retrieve Account Information</title>
</head>
<body>
    <h2>Retrieve Account Information</h2>
    <form method="post" action="">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username" required><br><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password" required><br><br>
        <label for="application_name">Application Name:</label><br>
        <input type="text" id="application_name" name="application_name" required><br><br>
        <label for="encryption_key">Encryption Key:</label><br>
        <input type="text" id="encryption_key" name="encryption_key" required><br><br>
        <input type="submit" value="Retrieve">
    </form>

    <?php if (!empty($auth_error)): ?>
        <p style="color: red;"><?php echo htmlspecialchars($auth_error); ?></p>
    <?php endif; ?>

    <?php if (!empty($account_info)): ?>
        <h2>Account Information for "<?php echo htmlspecialchars($application_name); ?>"</h2>
        <table border="1">
            <tr>
                <th>Account Name</th>
                <th>Password</th>
            </tr>
            <?php foreach ($account_info as $info): ?>
                <tr>
                    <td><?php echo htmlspecialchars($info['account_name']); ?></td>
                    <td><?php echo htmlspecialchars($info['password_hash']); ?></td>
                </tr>
            <?php endforeach; ?>
        </table>
    <?php endif; ?>

    <br>
    <a href="store_account.php">Store Account Information</a>
</body>
</html>
