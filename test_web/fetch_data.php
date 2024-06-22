<?php

$host = 'database-1.ci8xrzpcqftf.ap-northeast-2.rds.amazonaws.com';
$dbname = 'test_db';
$username = 'admin';
$password = 'sesac*1234';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $stmt = $pdo->query('SELECT * FROM user_data');
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if ($rows) {
        echo '<table border="1">';
        echo '<tr><th>ID</th><th>Name</th><th>Registration Number</th><th>Postal Code</th><th>Basic Address</th><th>Detailed Address</th><th>Bank Name</th><th>Bank Code</th><th>Account Number</th></tr>';
        foreach ($rows as $row) {
            echo '<tr>';
            echo '<td>' . htmlspecialchars($row['id']) . '</td>';
            echo '<td>' . htmlspecialchars($row['name']) . '</td>';
            echo '<td>' . htmlspecialchars($row['registration_number']) . '</td>';
            echo '<td>' . htmlspecialchars($row['postal_code']) . '</td>';
            echo '<td>' . htmlspecialchars($row['basic_address']) . '</td>';
            echo '<td>' . htmlspecialchars($row['detailed_address']) . '</td>';
            echo '<td>' . htmlspecialchars($row['bank_name']) . '</td>';
            echo '<td>' . htmlspecialchars($row['bank_code']) . '</td>';
            echo '<td>' . htmlspecialchars($row['account_number']) . '</td>';
            echo '</tr>';
        }
        echo '</table>';
    } else {
        echo 'No data found';
    }
} catch (PDOException $e) {
    echo 'Connection failed: ' . $e->getMessage();
}
?>
