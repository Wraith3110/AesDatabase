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

// Function to encrypt passwords
function encrypt_password($password, $key) {
    return openssl_encrypt($password, 'aes-256-cbc', $key, 0, '1234567890123456');
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $application_name = $_POST['application_name'];
    $account_name = $_POST['account_name'];
    $password = $_POST['password'];
    $encryption_key = $_POST['encryption_key'];

    // Encrypt the password
    $encrypted_password = encrypt_password($password, $encryption_key);

    // Prepare and bind
    $stmt = $conn->prepare("INSERT INTO accounts (application_name, account_name, password_hash) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $application_name, $account_name, $encrypted_password);

    // Execute the statement
    if ($stmt->execute()) {
        echo "New record created successfully";
    } else {
        echo "Error: " . $stmt->error;
    }

    // Close the statement
    $stmt->close();
}

// Retrieve account information
$sql = "SELECT application_name, account_name, password_hash FROM accounts";
$result = $conn->query($sql);

$conn->close();
?>

<!DOCTYPE html>
<html>
<head>
    <title>Store Account Information</title>
</head>
<body>
    <h2>Store Account Information</h2>
    <form method="post" action="">
        <label for="application_name">Application Name:</label><br>
        <input type="text" id="application_name" name="application_name" required><br><br>
        <label for="account_name">Account Name:</label><br>
        <input type="text" id="account_name" name="account_name" required><br><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password" required><br><br>
        <label for="encryption_key">Encryption Key:</label><br>
        <input type="text" id="encryption_key" name="encryption_key" required><br><br>
        <input type="submit" value="Submit">
    </form>

    <h2>Stored Accounts</h2>
    <table border="1">
        <tr>
            <th>Application Name</th>
            <th>Account Name</th>
            <th>Password (Encrypted)</th>
        </tr>
        <?php
        if ($result->num_rows > 0) {
            // Output data of each row
            while($row = $result->fetch_assoc()) {
                echo "<tr><td>" . htmlspecialchars($row["application_name"]) . "</td><td>" . htmlspecialchars($row["account_name"]) . "</td><td>" . htmlspecialchars($row["password_hash"]) . "</td></tr>";
            }
        } else {
            echo "<tr><td colspan='3'>No accounts stored</td></tr>";
        }
        ?>
    </table>

    <br>
    <a href="retrieve_account.php">Retrieve Account Information</a>
</body>
</html>
