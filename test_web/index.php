<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MySQL Data Fetch Example</title>
    <script>
        function fetchData() {
            const xhr = new XMLHttpRequest();
            xhr.open('GET', 'fetch_data.php', true);
            xhr.onload = function() {
                if (this.status === 200) {
                    document.getElementById('data-output').innerHTML = this.responseText;
                }
            };
            xhr.send();
        }
    </script>
</head>
<body>
    <h1>Fetch Data from MySQL</h1>
    <button onclick="fetchData()">Fetch Data</button>
    <div id="data-output"></div>
</body>
</html>
