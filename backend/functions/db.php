<?php
// pdo连接数据库
$db_host = DB_HOST;
$db_user = DB_USER;
$db_pass = DB_PASS;
$db_name = DB_NAME;
$pdo = 'mysql:host=' . $db_host . ';' . 'dbname=' . $db_name;
try {
    $pdo = new PDO($pdo, $db_user, $db_pass);
    // echo '连接成功';
} catch (PDOException $e) {
    // echo $e;
    echo '数据库连接失敗';
}
// 检查用户名是否重复
function is_user_repeat($key, $value)
{
    global $pdo;
    $value = $pdo->quote($value);
    $sqlco = "SELECT * FROM `user` WHERE `" . $key . "` = {$value}";
    $result = $pdo->query($sqlco);
    $result = $result->fetch();
    if ($result) {
        return 1;
    } else {
        return 0;
    }
}
// 注册用户
function user_register($username, $password, $email)
{
    global $pdo;
    $salt = cook_salt();
    $time = time();
    $token = md5($username . '.' . $time . '.' . $salt);
    $sql = "INSERT INTO `user` (`username`,`mail`,`password`,`level`,`token`,`regist_date`,`latest_date`,`salt`) VALUES (?,?,?,?,?,?,?,?)";
    $stmt = $pdo->prepare($sql);
    $stmt->bindParam(1, $username);
    $stmt->bindParam(2, $email);
    $stmt->bindParam(3, $password);
    $stmt->bindValue(4, '-1');
    $stmt->bindParam(5, $token);
    $stmt->bindParam(6, $time);
    $stmt->bindParam(7, $time);
    $stmt->bindParam(8, $salt);
    $stmt->execute();
    return $token;
}
// 用户登录
function user_login($username, $password)
{
    global $pdo;
    $sqlco = "SELECT * FROM `user` WHERE `username` = ?";
    $result = $pdo->prepare($sqlco);
    $result->execute(array($username));
    $result = $result->fetch();
    if ($result) {
        if ($password == $result['password']) {
            $salt = cook_salt();
            $time = time();
            $token = md5($username . '.' . $time . '.' . $salt);
            $sql = "UPDATE `user` SET `latest_date` = '" . $time . "', `token` = '" . $token . "',`salt` = '" . $salt . "' WHERE `username` = '" . $username . "';";
            $pdo->exec($sql);
            return $token;
        } else {
            return 0;
        }
    } else {
        return -1;
    }
}
// 确认登录状态
function confirm_login($token)
{
    global $pdo;
    $sqlco = "SELECT * FROM `user` WHERE `token` = ?";
    $result = $pdo->prepare($sqlco);
    $result->execute(array($token));
    $result = $result->fetch();
    // 后续可以添加过期时间
    if ($result) {
        return 1;
    } else {
        return 0;
    }
}
// 用户登出
function user_logout($token)
{
    global $pdo;
    $sql = "UPDATE `user` SET `token` = '' WHERE `token` = ? ;";
    $result = $pdo->prepare($sql);
    $result->execute(array($token));
}
// 用户信息查询（利用token）
function user_info($token)
{
    global $pdo;
    $sqlco = "SELECT * FROM `user` WHERE `token` = ?";
    $result = $pdo->prepare($sqlco);
    $result->execute(array($token));
    $result = $result->fetch();
    return $result;
}
// 新建验证码（利用token）
function creat_confirm_key($token)
{
    global $pdo;
    $result = user_info($token);
    $uid = $result['id'];
    $sqlco = "SELECT * FROM `mail_confirm` WHERE `uid` = ? AND `type` = '1'";
    $result = $pdo->prepare($sqlco);
    $result->execute(array($uid));
    $result = $result->fetch();
    if ($result) {
        $access_key = $result['access_key'];
        if ($result['expire_date'] < time()) {
            $access_key = md5(time() . cook_salt());
            $sql = "UPDATE `mail_confirm` SET `access_key` = '" . $access_key . "' , `expire_date` = '" . (time() + 300) . "' WHERE `uid` = '" . $uid . "' AND `type` = '1';";
            $pdo->exec($sql);
        }
    } else {
        $access_key = md5(time() . cook_salt());
        $sql = "INSERT INTO `mail_confirm` (`uid`,`access_key`,`expire_date`,`type`) VALUES ('" . $uid . "','" . $access_key . "','" . (time() + 300) . "','1')";
        $pdo->exec($sql);
    }
    return $access_key;
}
// 寻找验证码（利用token）
function search_confirm_key($token)
{
    global $pdo;
    $result = user_info($token);
    $uid = $result['id'];
    $sqlco = "SELECT * FROM `mail_confirm` WHERE `uid` = ? AND `type` = '1'";
    $result = $pdo->prepare($sqlco);
    $result->execute(array($uid));
    $result = $result->fetch();
    return $result;
}
// 提升用户等级（利用token）
function update_user_level($token, $level)
{
    global $pdo;
    $sql = "UPDATE `user` SET `level` = ? WHERE `token` = ? ;";
    $result = $pdo->prepare($sql);
    $result->execute(array($level, $token));
}
// 修改密码（利用token）
function update_user_password($token, $password)
{
    global $pdo;
    $sql = "UPDATE `user` SET `password` = ? WHERE `token` = ? ;";
    $result = $pdo->prepare($sql);
    $result->execute(array($password, $token));
}
// 修改邮箱
function update_user_email($token, $email)
{
    global $pdo;
    $sql = "UPDATE `user` SET `mail` = ? WHERE `token` = ? ;";
    $result = $pdo->prepare($sql);
    $result->execute(array($email, $token));
}
// 用户信息查询（利用邮箱）
function user_info_email($email)
{
    global $pdo;
    $sqlco = "SELECT * FROM `user` WHERE `mail` = ?";
    $result = $pdo->prepare($sqlco);
    $result->execute(array($email));
    $result = $result->fetch();
    return $result;
}
// 检测邮箱是否存在
function is_email_exist($email)
{
    global $pdo;
    $sqlco = "SELECT * FROM `user` WHERE `mail` = '" . $email . "'";
    $result = $pdo->prepare($sqlco);
    $result->execute(array($email));
    $result = $result->fetch();
    if (!$result) {
        return 0;
    } else {
        return 1;
    }
}
// 新建验证码（利用邮箱）
function creat_confirm_key_email($email)
{
    global $pdo;
    $result = user_info_email($email);
    $uid = $result['id'];
    $sqlco = "SELECT * FROM `mail_confirm` WHERE `uid` = ? AND `type` = '2'";
    $result = $pdo->prepare($sqlco);
    $result->execute(array($uid));
    $result = $result->fetch();
    if ($result) {
        $access_key = $result['access_key'];
        if ($result['expire_date'] < time()) {
            $access_key = md5(time() . cook_salt());
            $sql = "UPDATE `mail_confirm` SET `access_key` = '" . $access_key . "' , `expire_date` = '" . (time() + 300) . "' WHERE `uid` = '" . $uid . "' AND `type` = '2';";
            $pdo->exec($sql);
        }
    } else {
        $access_key = md5(time() . cook_salt());
        $sql = "INSERT INTO `mail_confirm` (`uid`,`access_key`,`expire_date`,`type`) VALUES ('" . $uid . "','" . $access_key . "','" . (time() + 300) . "','2')";
        $pdo->exec($sql);
    }
    return $access_key;
}
// 寻找验证码（利用邮箱）
function search_confirm_key_email($email)
{
    global $pdo;
    $result = user_info_email($email);
    $uid = $result['id'];
    $sqlco = "SELECT * FROM `mail_confirm` WHERE `uid` = ? AND `type` = '2'";
    $result = $pdo->prepare($sqlco);
    $result->execute(array($uid));
    $result = $result->fetch();
    return $result;
}
// 修改密码（利用邮箱）
function update_user_password_email($email, $password)
{
    global $pdo;
    $sql = "UPDATE `user` SET `password` = ? WHERE `email` = ? ;";
    $result = $pdo->prepare($sql);
    $result->execute(array($password, $email));
}
// 删除验证码
function delete_access_key($uid, $type)
{
    global $pdo;
    $sql = "DELETE FROM `mail_confirm` WHERE `uid` = '" . $uid . "' AND `type` = '" . $type . "'";
    $pdo->exec($sql);
}
// 新建剪贴板
function add_pastebin($uid, $encryption, $password, $alias, $title, $text)
{
    global $pdo;
    $sql = "INSERT INTO `pastebin` (`uid`,`alias`,`encryption`,`password`,`title`,`text`) VALUES (?,?,?,?,?,?)";
    $stmt = $pdo->prepare($sql);
    $stmt->bindParam(1, $uid);
    $stmt->bindParam(2, $alias);
    $stmt->bindParam(3, $encryption);
    $stmt->bindParam(4, $password);
    $stmt->bindParam(5, $title);
    $stmt->bindParam(6, $text);
    $stmt->execute();
}
// 更新剪贴板
function update_pastebin($id, $type, $value)
{
    global $pdo;
    $value = $pdo->quote($value);
    $sql = "UPDATE `pastebin` SET `" . $type . "` = " . $value . " WHERE `id` = '" . $id . "';";
    $pdo->exec($sql);
}
// 获取用户所有的剪贴板
function search_user_pastebin($uid)
{
    global $pdo;
    $sqlco = "SELECT * FROM `pastebin` WHERE `uid` = ?";
    $result = $pdo->prepare($sqlco);
    $result->execute(array($uid));
    $result = $result->fetchAll();
    return $result;
}
// 获取剪贴板信息（通过id）
function pastebin_info_id($id)
{
    global $pdo;
    $sqlco = "SELECT * FROM `pastebin` WHERE `id` = ?";
    $result = $pdo->prepare($sqlco);
    $result->execute(array($id));
    $result = $result->fetch();
    return $result;
}
// 获取剪贴板信息（通过缩写）
function pastebin_info_alias($alias)
{
    global $pdo;
    $sqlco = "SELECT * FROM `pastebin` WHERE `alias` = ?";
    $result = $pdo->prepare($sqlco);
    $result->execute(array($alias));
    $result = $result->fetch();
    return $result;
}
// 删除剪贴板
function delete_pastebin($id)
{
    global $pdo;
    $sql = "DELETE FROM `pastebin` WHERE `id` = ?";
    $result = $pdo->prepare($sql);
    $result->execute(array($id));
}
