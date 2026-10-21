<?php
header('Content-Type: application/json');
$out = ['post' => array_keys($_POST), 'files' => array_keys($_FILES), 'sess' => session_status()];
session_start();
$out['keys'] = array_slice(array_keys($_SESSION), 0, 5);
$out['count'] = count($_SESSION);
echo json_encode($out), "\n";
