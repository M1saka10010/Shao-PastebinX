<?php
include 'config.php';
include 'functions/db.php';
include 'functions/function.php';
if (!isset($_POST['type'])) {
    $data = array('code' => 400, 'message' => 'Missing value of type.');
    $json = json_encode($data);
    exit($json);
}
switch ($_POST['type']) {
    case "add": // 新增剪贴板
        if (!isset($_POST['token']) || !isset($_POST['title']) || !isset($_POST['text']) || !isset($_POST['encryption']) || empty($_POST['token']) || $_POST['title'] == "" || $_POST['text'] == "") {
            $data = array('code' => 400, 'message' => 'Missing value(s).');
            $json = json_encode($data);
            exit($json);
        } else if (!confirm_login($_POST['token'])) {
            $data = array('code' => 415, 'message' => 'Do not logged in.');
            $json = json_encode($data);
            exit($json);
        } else if (strlen($_POST['title']) > 100) {
            $data = array('code' => 420, 'message' => 'Title too long.');
            $json = json_encode($data);
            exit($json);
        } else if (strlen($_POST['text']) > 1048576 * 8) {
            $data = array('code' => 421, 'message' => 'Text too long.');
            $json = json_encode($data);
            exit($json);
        } else if (isset($_POST['password']) && strlen($_POST['password']) > 32) {
            $data = array('code' => 422, 'message' => 'Password too long.');
            $json = json_encode($data);
            exit($json);
        } else if (isset($_POST['alias']) && strlen($_POST['alias']) > 20) {
            $data = array('code' => 423, 'message' => 'Alias too long.');
            $json = json_encode($data);
            exit($json);
        } else if ($_POST['encryption'] == 1 && (!isset($_POST['password']) || empty($_POST['password']))) {
            $data = array('code' => 424, 'message' => 'Unsupport empty password.');
            $json = json_encode($data);
            exit($json);
        }
        $data = user_info($_POST['token']);
        if ($data['level'] == -1) {
            $data = array('code' => 425, 'message' => 'Please confirm your email first.');
            $json = json_encode($data);
            exit($json);
        }
        if ($_POST['encryption'] == 1) {
            if (!isset($_POST['alias']) || empty($_POST['alias'])) {
                add_pastebin($data['id'], 1, $_POST['password'], '', $_POST['title'], base64_encode($_POST['text']));
                $data = array('code' => 0, 'message' => 'Successfully add pastebin.');
                $json = json_encode($data);
                exit($json);
            } else {
                if (pastebin_info_alias($_POST['alias']) || is_numeric($_POST['alias'])) {
                    $data = array('code' => 426, 'message' => 'This alias has been taken.');
                    $json = json_encode($data);
                    exit($json);
                } else {
                    add_pastebin($data['id'], 1, $_POST['password'], $_POST['alias'], $_POST['title'], base64_encode($_POST['text']));
                    $data = array('code' => 0, 'message' => 'Successfully add pastebin.');
                    $json = json_encode($data);
                    exit($json);
                }
            }
        } else {
            if (!isset($_POST['alias']) || empty($_POST['alias'])) {
                add_pastebin($data['id'], 0, '', '', $_POST['title'], base64_encode($_POST['text']));
                $data = array('code' => 0, 'message' => 'Successfully add pastebin.');
                $json = json_encode($data);
                exit($json);
            } else {
                if (pastebin_info_alias($_POST['alias']) || is_numeric($_POST['alias'])) {
                    $data = array('code' => 426, 'message' => 'This alias has been taken.');
                    $json = json_encode($data);
                    exit($json);
                } else {
                    add_pastebin($data['id'], 0, '', $_POST['alias'], $_POST['title'], base64_encode($_POST['text']));
                    $data = array('code' => 0, 'message' => 'Successfully add pastebin.');
                    $json = json_encode($data);
                    exit($json);
                }
            }
        }
        break;
    case "update": // 更新剪贴板
        if (!isset($_POST['token']) || !isset($_POST['id']) || !isset($_POST['title']) || !isset($_POST['text']) || !isset($_POST['encryption']) || empty($_POST['token']) || empty($_POST['id']) || $_POST['title'] == "" || $_POST['text'] == "") {
            $data = array('code' => 400, 'message' => 'Missing value(s)');
            $json = json_encode($data);
            exit($json);
        } else if (!confirm_login($_POST['token'])) {
            $data = array('code' => 415, 'message' => 'Do not logged in.');
            $json = json_encode($data);
            exit($json);
        } else if (strlen($_POST['title']) > 100) {
            $data = array('code' => 420, 'message' => 'Title too long.');
            $json = json_encode($data);
            exit($json);
        } else if (strlen($_POST['text']) > 1048576 * 8) {
            $data = array('code' => 421, 'message' => 'Text too long.');
            $json = json_encode($data);
            exit($json);
        } else if (isset($_POST['password']) && strlen($_POST['password']) > 32) {
            $data = array('code' => 422, 'message' => 'Password too long.');
            $json = json_encode($data);
            exit($json);
        } else if (isset($_POST['alias']) && strlen($_POST['alias']) > 20) {
            $data = array('code' => 423, 'message' => 'Alias too long.');
            $json = json_encode($data);
            exit($json);
        } else if ($_POST['encryption'] == 1 && (!isset($_POST['password']) || empty($_POST['password'])) && empty(pastebin_info_id($_POST['id'])['password'])) {
            $data = array('code' => 424, 'message' => 'Unsupport empty password.');
            $json = json_encode($data);
            exit($json);
        }
        $data = user_info($_POST['token']);
        if ($data['level'] == -1) {
            $data = array('code' => 425, 'message' => 'Please confirm your email first.');
            $json = json_encode($data);
            exit($json);
        }
        $p_data = pastebin_info_id($_POST['id']);
        if ($p_data['uid'] != $data['id']) {
            $data = array('code' => 426, 'message' => 'This pastebin isn\'t yours.');
            $json = json_encode($data);
            exit($json);
        }
        if ($_POST['encryption'] == 1) {
            if (!isset($_POST['alias']) || empty($_POST['alias'])) {
                update_pastebin($_POST['id'], 'title', $_POST['title']);
                update_pastebin($_POST['id'], 'text', base64_encode($_POST['text']));
                update_pastebin($_POST['id'], 'encryption', 1);
                if (isset($_POST['password']) && $_POST['password'] != "") {
                    update_pastebin($_POST['id'], 'password', $_POST['password']);
                }
                $data = array('code' => 0, 'message' => 'Successfully updated pastebin.');
                $json = json_encode($data);
                exit($json);
            } else {
                if ((pastebin_info_alias($_POST['alias']) && $p_data['alias'] != $_POST['alias']) || is_numeric($_POST['alias'])) {
                    $data = array('code' => 426, 'message' => 'This alias has been taken.');
                    $json = json_encode($data);
                    exit($json);
                } else {
                    update_pastebin($_POST['id'], 'title', $_POST['title']);
                    update_pastebin($_POST['id'], 'text', base64_encode($_POST['text']));
                    update_pastebin($_POST['id'], 'encryption', 1);
                    if (isset($_POST['password']) && $_POST['password'] != "") {
                        update_pastebin($_POST['id'], 'password', $_POST['password']);
                    }
                    update_pastebin($_POST['id'], 'alias', $_POST['alias']);
                    $data = array('code' => 0, 'message' => 'Successfully updated pastebin.');
                    $json = json_encode($data);
                    exit($json);
                }
            }
        } else {
            if (!isset($_POST['alias']) || empty($_POST['alias'])) {
                update_pastebin($_POST['id'], 'title', $_POST['title']);
                update_pastebin($_POST['id'], 'text', base64_encode($_POST['text']));
                update_pastebin($_POST['id'], 'encryption', 0);
                update_pastebin($_POST['id'], 'password', '');
                $data = array('code' => 0, 'message' => 'Successfully updated pastebin.');
                $json = json_encode($data);
                exit($json);
            } else {
                if ((pastebin_info_alias($_POST['alias']) && $p_data['alias'] != $_POST['alias']) || is_numeric($_POST['alias'])) {
                    $data = array('code' => 426, 'message' => 'This alias has been taken.');
                    $json = json_encode($data);
                    exit($json);
                } else {
                    update_pastebin($_POST['id'], 'title', $_POST['title']);
                    update_pastebin($_POST['id'], 'text', base64_encode($_POST['text']));
                    update_pastebin($_POST['id'], 'encryption', 0);
                    update_pastebin($_POST['id'], 'password', '');
                    update_pastebin($_POST['id'], 'alias', $_POST['alias']);
                    $data = array('code' => 0, 'message' => 'Successfully updated pastebin.');
                    $json = json_encode($data);
                    exit($json);
                }
            }
        }
        break;
    case "list": // 获取当前用户所有剪贴板
        if (!isset($_POST['token']) || empty($_POST['token'])) {
            $data = array('code' => 400, 'message' => 'Missing value(s).');
            $json = json_encode($data);
            exit($json);
        } else if (!confirm_login($_POST['token'])) {
            $data = array('code' => 415, 'message' => 'Do not logged in.');
            $json = json_encode($data);
            exit($json);
        }
        $data = user_info($_POST['token']);
        $result = search_user_pastebin($data['id']);
        $list = array();
        for ($i = 0; $i < count($result); $i++) {
            $list[$i] = array($result[$i]['id'], $result[$i]['title'], $result[$i]['encryption'], $result[$i]['password'], $result[$i]['alias']);
        }
        $data = array('code' => 0, 'data' => $list);
        $json = json_encode($data);
        exit($json);
        break;
    case "delete": // 删除剪贴板
        if (!isset($_POST['token']) || !isset($_POST['id'])  || empty($_POST['token']) || empty($_POST['id'])) {
            $data = array('code' => 400, 'message' => 'Missing value(s).');
            $json = json_encode($data);
            exit($json);
        } else if (!confirm_login($_POST['token'])) {
            $data = array('code' => 415, 'message' => 'Do not logged in.');
            $json = json_encode($data);
            exit($json);
        }
        $data = user_info($_POST['token']);
        if ($data['level'] == -1) {
            $data = array('code' => 425, 'message' => 'Please confirm your email first.');
            $json = json_encode($data);
            exit($json);
        }
        $p_data = pastebin_info_id($_POST['id']);
        if ($p_data) {
            if ($p_data['uid'] != $data['id']) {
                $data = array('code' => 426, 'message' => 'This pastebin isn\'t yours.');
                $json = json_encode($data);
                exit($json);
            } else {
                delete_pastebin($_POST['id']);
                $data = array('code' => 0, 'message' => 'Deleted successfully.');
                $json = json_encode($data);
                exit($json);
            }
        } else {
            $data = array('code' => 427, 'message' => 'This pastebin isn\'t exists.');
            $json = json_encode($data);
            exit($json);
        }
        break;
    case "info": // 获取剪贴板内容
        if ((!isset($_POST['id']) || empty($_POST['id'])) && (!isset($_POST['alias']) || empty($_POST['alias']))) {
            $data = array('code' => 400, 'message' => 'Missing value(s).');
            $json = json_encode($data);
            exit($json);
        } else {
            if (!empty($_POST['id'])) {
                $p_data = pastebin_info_id($_POST['id']);
            } else if (!empty($_POST['alias'])) {
                $p_data = pastebin_info_alias($_POST['alias']);
            }
            if ($p_data) {
                if (isset($_POST['token']) && !empty($_POST['token'])) {
                    $data = user_info($_POST['token']);
                }
                if ($p_data['encryption'] == 0 || (isset($data) && !empty($data) && $data['id'] == $p_data['uid'])) {
                    $data = array('code' => 0, 'id' => $p_data['id'], 'alias' => $p_data['alias'], 'encryption' => $p_data['encryption'], 'title' => $p_data['title'], 'text' => base64_decode($p_data['text']));
                    $json = json_encode($data);
                    exit($json);
                } else if (!isset($_POST['password']) || empty($_POST['password'])) {
                    $data = array('code' => 428, 'message' => 'Empty password.');
                    $json = json_encode($data);
                    exit($json);
                } else if ($_POST['password'] != $p_data['password']) {
                    $data = array('code' => 429, 'message' => 'Wrong password.');
                    $json = json_encode($data);
                    exit($json);
                } else {
                    $data = array('code' => 0, 'id' => $p_data['id'], 'alias' => $p_data['alias'], 'title' => $p_data['title'], 'text' => base64_decode($p_data['text']));
                    $json = json_encode($data);
                    exit($json);
                }
            } else {
                $data = array('code' => 427, 'message' => 'This pastebin isn\'t exists.');
                $json = json_encode($data);
                exit($json);
            }
        }
        break;
    default:
        $data = array('code' => 400, 'message' => 'Wrong value of type.');
        $json = json_encode($data);
        exit($json);
}
