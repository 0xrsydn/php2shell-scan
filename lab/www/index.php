<?php
$out = [
  'm' => $_SERVER['REQUEST_METHOD'],
  'post' => array_keys($_POST),
  'files' => array_keys($_FILES),
  'sess' => session_status(),
  'pid' => getmypid(),
];
if (!empty($_GET['sess'])) {
  session_start();
  $out['session_keys'] = array_slice(array_keys($_SESSION), 0, 8);
  $out['session_count'] = count($_SESSION);
}
header('Content-Type: application/json');
echo json_encode($out), "\n";
