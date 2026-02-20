
<?php
require "admin/db.php";   // ✅ correct file

$error = "";
$success = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_GET['action'])) {
        if ($_GET['action'] == 'register') {
            $errors = [];
            $username = trim($_POST["username"] ?? '');
            $raw_password = $_POST["password"] ?? '';
            $role = $_POST["role"] ?? '';
            $fullname = trim($_POST["fullname"] ?? '');
            $gender = $_POST["gender"] ?? '';
            $class_id = $_POST["class_id"] ?? '';
            $roll = trim($_POST["roll"] ?? '');

            if (empty($username)) {
                $errors['username'] = "Username is required.";
            }
            if (empty($raw_password)) {
                $errors['password'] = "Password is required.";
            } elseif (strlen($raw_password) < 6 || !preg_match('/\d/', $raw_password)) {
                $errors['password'] = "Password must be at least 6 characters and include at least one number.";
            }
            if (empty($role)) {
                $errors['role'] = "Role is required.";
            }
            if (empty($fullname)) {
                $errors['fullname'] = "Full name is required.";
            }
            if ($role == 'student') {
                if (empty($gender)) {
                    $errors['gender'] = "Gender is required.";
                }
                if (empty($class_id)) {
                    $errors['class_id'] = "Class is required.";
                }
                if (empty($roll)) {
                    $errors['roll'] = "Roll is required.";
                } elseif (!ctype_digit($roll)) {
                    $errors['roll'] = "Roll must be a number.";
                }
            }

            if (empty($errors)) {
                // Check if username exists
                $stmt = $conn->prepare("SELECT id FROM users WHERE username=?");
                $stmt->bind_param("s", $username);
                $stmt->execute();
                if ($stmt->get_result()->num_rows == 0) {
                    // Insert user
                    $password = password_hash($raw_password, PASSWORD_DEFAULT);
                    $stmt = $conn->prepare("INSERT INTO users(username,password,role) VALUES(?,?,?)");
                    $stmt->bind_param("sss", $username, $password, $role);
                    $stmt->execute();
                    $user_id = $conn->insert_id;

                    if ($role == 'student') {
                        // Insert student (include roll)
                        $stmt2 = $conn->prepare("INSERT INTO students(user_id,full_name,gender,class_id,roll) VALUES(?,?,?,?,?)");
                        $stmt2->bind_param("issis", $user_id, $fullname, $gender, $class_id, $roll);
                        $stmt2->execute();
                    } elseif ($role == 'teacher') {
                        // Insert teacher
                        $stmt2 = $conn->prepare("INSERT INTO teachers(user_id,full_name) VALUES(?,?)");
                        $stmt2->bind_param("is", $user_id, $fullname);
                        $stmt2->execute();
                    }
                    // For admin, no extra table

                    // Auto login after registration
                    $_SESSION["user_id"] = $user_id;
                    $_SESSION["role"] = $role;
                    $_SESSION["username"] = $username;

                    if ($role == "admin") {
                        header("Location: admin/dashboard.php");
                    } elseif ($role == "teacher") {
                        header("Location: admin/teacher/dashbord.php");
                    } else {
                        header("Location: admin/teacher/student/dashbord.php");
                    }
                    exit();
                } else {
                    $errors['username'] = "Username already exists.";
                }
            }
        } elseif ($_GET['action'] == 'forgot') {
            $username = trim($_POST["username"] ?? '');
            $new_password = $_POST["new_password"] ?? '';
            if ($username && $new_password) {
                if (strlen($new_password) < 6 || !preg_match('/\d/', $new_password)) {
                    $error = 'New password must be at least 6 characters and include at least one number.';
                } else {
                    $newpass = password_hash($new_password, PASSWORD_DEFAULT);
                    $stmt = $conn->prepare("UPDATE users SET password=? WHERE username=?");
                    $stmt->bind_param("ss", $newpass, $username);
                    $stmt->execute();
                }
                if ($stmt->affected_rows > 0) {
                    // Fetch user to auto-login
                    $stmt2 = $conn->prepare("SELECT id, role, username FROM users WHERE username=?");
                    $stmt2->bind_param("s", $username);
                    $stmt2->execute();
                    $res = $stmt2->get_result();
                    if ($res && $res->num_rows == 1) {
                        $user = $res->fetch_assoc();
                        $_SESSION["user_id"] = $user['id'];
                        $_SESSION["role"] = $user['role'];
                        $_SESSION["username"] = $user['username'];
                        if ($user['role'] == "admin") {
                            header("Location: admin/dashboard.php");
                        } elseif ($user['role'] == "teacher") {
                            header("Location: admin/teacher/dashbord.php");
                        } else {
                            header("Location: admin/teacher/student/dashbord.php");
                        }
                        exit();
                    } else {
                        $success = "Password reset successfully. Please login with your new password.";
                    }
                } else {
                    $error = "Username not found";
                }
            } else {
                $error = "Username and new password required";
            }
        }
    } else {
        // Login logic
        $username = trim($_POST["username"] ?? '');
        $password = $_POST["password"] ?? '';

        if (empty($username) || empty($password)) {
            $error = "All fields required";
        } else {
            // Try username lookup first
            $stmt = $conn->prepare("SELECT * FROM users WHERE username=?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();

            $user = null;
            if ($result && $result->num_rows == 1) {
                $user = $result->fetch_assoc();
            } else {
                // If username lookup failed, try roll lookup for students (match by roll)
                $stmt2 = $conn->prepare("SELECT u.* FROM users u JOIN students s ON s.user_id = u.id WHERE TRIM(s.roll) = TRIM(?)");
                $stmt2->bind_param("s", $username);
                $stmt2->execute();
                $r2 = $stmt2->get_result();
                if ($r2) {
                    if ($r2->num_rows == 1) {
                        $user = $r2->fetch_assoc();
                    } elseif ($r2->num_rows > 1) {
                        // multiple users with same roll - try to find which matches the provided password
                        $matched = null;
                        $matches = 0;
                        while ($row = $r2->fetch_assoc()) {
                            if (password_verify($password, $row['password'])) {
                                $matched = $row;
                                $matches++;
                            }
                        }
                        if ($matches == 1) {
                            $user = $matched;
                        } elseif ($matches > 1) {
                            $error = "Multiple users match these credentials — contact admin.";
                        } else {
                            $error = "Wrong password";
                        }
                    }
                }
            }

            if ($user) {
                if (password_verify($password, $user["password"])) {
                    $_SESSION["user_id"] = $user["id"];
                    $_SESSION["role"] = $user["role"];
                    $_SESSION["username"] = $user["username"];

                    if ($user["role"] == "admin") {
                        header("Location: admin/dashboard.php");
                    } elseif ($user["role"] == "teacher") {
                        header("Location: admin/teacher/dashbord.php");
                    } else {
                        header("Location: admin/teacher/student/dashbord.php");
                    }
                    exit();
                } else {
                    $error = "Wrong password";
                }
            } else {
                $error = "User not found";
            }
        }
    }
}
?>

<?php
// Fetch classes for register
$classes = $conn->query("SELECT id, class_name FROM classes WHERE class_name IN ('9', '10', '11', '12', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J')");
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>School Management Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: rgb(244,244,244); display: flex; justify-content: center; align-items: center; height: 100vh; flex-direction: column; }
        nav { position: absolute; top: 10px; width: 100%; text-align: center; }
        nav a { margin: 0 10px; color: rgb(0,123,255); text-decoration: none; }
        nav a:hover { text-decoration: underline; }
        /* Apply container styles directly to tab-content since .container was removed */
        .tab-content { background: rgb(255,255,255); padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); width: 300px; margin: 50px auto 0; }
        h2 { text-align: center; }
        form { display: flex; flex-direction: column; }
        input { margin: 10px 0; padding: 10px; }
        button { padding: 10px; background: rgb(0,123,255); color: rgb(255,255,255); border: none; cursor: pointer; }
        button:hover { background: rgb(0,86,179); }
        .error { color: rgb(255,0,0); text-align: center; }
        .tabs { display: flex; justify-content: space-around; margin-bottom: 20px; }
        .tab { cursor: pointer; padding: 10px; background: rgb(221,221,221); }
        .tab.active { background: rgb(0,123,255); color: rgb(255,255,255); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
</head>
<body>



<div id="login" class="tab-content active">
          
            <form id="loginForm" method="post" autocomplete="on">
             <center><img src="download (1).jfif" alt="School Logo" width="100px" height="100px"></center>
                <input type="text" name="username" placeholder="Username" autocomplete="username" required>
                <input type="password" name="password" placeholder="Password" autocomplete="current-password" required>
                <div style="text-align:center; margin-top:6px;"><span id="loginMsg" style="color: rgb(0,123,255); display:none;">Logging in…</span></div>
                <button id="loginBtn" type="submit">Login</button>
                <div style="text-align:center; margin-top:8px;">
                    <a href="#register" onclick="showTab('register'); return false;">Create Account</a> |
                    <a href="#forgot" onclick="showTab('forgot'); return false;">Forgot Password</a> |
                    <a href="#login" onclick="showTab('login'); return false;">Login</a>
                </div>
            </form>
            <?php if ($error) echo "<p class='error'>$error</p>"; ?>
            <?php if ($success) echo "<p style='color: rgb(0,128,0); text-align: center;'>$success</p>"; ?>
        </div>
        
        <div id="register" class="tab-content">
            <h2>Create Account</h2>
            <form method="post" action="?action=register" autocomplete="on">
                <select name="role" required>
                    <option value="">Select Role</option>
                    <option value="admin">Admin</option>
                    <option value="teacher">Teacher</option>
                    <option value="student">Student</option>
                </select>
                <?php if (isset($errors['role'])): ?>
                    <p class="error"><?= $errors['role'] ?></p>
                <?php endif; ?>
                <input type="text" name="username" placeholder="Username" autocomplete="username" required>
                <?php if (isset($errors['username'])): ?>
                    <p class="error"><?= $errors['username'] ?></p>
                <?php endif; ?>
                <input type="password" name="password" placeholder="Password" autocomplete="new-password" required pattern="(?=.*\d).{6,}" title="At least 6 characters and include at least one number">
                <?php if (isset($errors['password'])): ?>
                    <p class="error"><?= $errors['password'] ?></p>
                <?php endif; ?>
                <input type="text" name="fullname" placeholder="Full Name" required>
                <?php if (isset($errors['fullname'])): ?>
                    <p class="error"><?= $errors['fullname'] ?></p>
                <?php endif; ?>
                <select name="gender">
                    <option value="">Select Gender</option>
                    <option value="male">Male</option>
                    <option value="female">Female</option>
                </select>
                <?php if (isset($errors['gender'])): ?>
                    <p class="error"><?= $errors['gender'] ?></p>
                <?php endif; ?>
                <select name="class_id" id="class_id" style="display:none;">
                    <option value="">Select Class</option>
                    <?php $classes->data_seek(0); while($class = $classes->fetch_assoc()): ?>
                    <option value="<?= $class['id'] ?>"><?= htmlspecialchars($class['class_name']) ?></option>
                    <?php endwhile; ?>
                </select>
                <?php if (isset($errors['class_id'])): ?>
                    <p class="error"><?= $errors['class_id'] ?></p>
                <?php endif; ?>
                <input type="text" name="roll" id="roll" placeholder="Roll Number" style="display:none;">
                <?php if (isset($errors['roll'])): ?>
                    <p class="error"><?= $errors['roll'] ?></p>
                <?php endif; ?>
                <button type="submit">Create Account</button>
            </form>
        </div>
        
        <div id="forgot" class="tab-content">
            <h2>Forgot Password</h2>
            <form method="post" action="?action=forgot" autocomplete="on">
                <input type="text" name="username" placeholder="Username" autocomplete="username" required>
                <input type="password" name="new_password" placeholder="New Password" autocomplete="new-password" required pattern="(?=.*\d).{6,}" title="At least 6 characters and include at least one number">
                <button type="submit">Reset Password</button>
            </form>
        </div>
    <script>
        function showTab(tab) {
            if (!tab) return;
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            var tabBtn = document.querySelector(`[onclick="showTab('${tab}')"]`);
            if (tabBtn) tabBtn.classList.add('active');
            var tabContent = document.getElementById(tab);
            if (tabContent) tabContent.classList.add('active');
        }
        // On load, show tab from hash or default to login
        document.addEventListener('DOMContentLoaded', function(){
            var hash = location.hash ? location.hash.replace('#','') : '';
            if (hash && (hash === 'login' || hash === 'register' || hash === 'forgot')) {
                showTab(hash);
            } else {
                showTab('login');
            }

            // Show a message when login button is clicked and disable to prevent double submits
            var loginForm = document.getElementById('loginForm');
            var loginBtn = document.getElementById('loginBtn');
            var loginMsg = document.getElementById('loginMsg');
            if (loginForm && loginBtn && loginMsg) {
                loginForm.addEventListener('submit', function(e){
                    loginMsg.style.display = 'inline';
                    loginBtn.disabled = true;
                });
            }

            // Show class select when student is selected
            var roleSelect = document.querySelector('select[name="role"]');
            var classSelect = document.getElementById('class_id');
            var rollInput = document.getElementById('roll');
            if (roleSelect && classSelect && rollInput) {
                roleSelect.addEventListener('change', function() {
                    if (this.value === 'student') {
                        classSelect.style.display = 'block';
                        rollInput.style.display = 'block';
                    } else {
                        classSelect.style.display = 'none';
                        rollInput.style.display = 'none';
                    }
                });
            }
        });
    </script>
</body>
</html>
