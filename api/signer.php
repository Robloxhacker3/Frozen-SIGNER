<?php
// api/signer.php
// Simple file-storage API for FROZEN SIGNER (IPA signing orchestrator).
// Requirements: PHP 7+, file write permission in storage/, exec() available.
// NOTE: The actual signing is delegated to a shell script invoked below.
// Secure this API before production (authentication, HTTPS, input validation).

header('Content-Type: application/json');

// Basic router using ?action=
$action = $_GET['action'] ?? '';

$baseDir = __DIR__ . '/../storage';
$ipadir = $baseDir . '/ipas';
$p12dir = $baseDir . '/p12s';
$provdir = $baseDir . '/mobileprovisions';
$jobsdir = $baseDir . '/jobs';

// ensure dirs exist
foreach ([$baseDir, $ipadir, $p12dir, $provdir, $jobsdir] as $d) {
    if (!is_dir($d)) mkdir($d, 0775, true);
}

function json($o) { echo json_encode($o); exit; }

switch ($action) {
    case 'ping':
        json(['ok' => true, 'ts' => time()]);
        break;

    // 1) Repo registration (user pastes GitHub repo URL to download .ipa from)
    case 'register_repo':
        // expects POST JSON { "repo_url": "https://github.com/owner/repo", "path": "path/to/ipa" }
        $body = json_decode(file_get_contents('php://input'), true);
        if (!$body || empty($body['repo_url'])) json(['error' => 'repo_url required']);
        $id = 'repo-' . substr(md5($body['repo_url'] . rand()), 0, 10);
        $record = [
            'id' => $id,
            'repo_url' => $body['repo_url'],
            'path' => $body['path'] ?? '',
            'created_at' => time()
        ];
        file_put_contents("$baseDir/$id.json", json_encode($record, JSON_PRETTY_PRINT));
        json(['ok' => true, 'record' => $record]);
        break;

    // 2) Upload IPA
    case 'upload_ipa':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') json(['error' => 'Use POST with multipart']);
        if (!isset($_FILES['file'])) json(['error' => 'file field required']);
        $f = $_FILES['file'];
        if ($f['error'] !== UPLOAD_ERR_OK) json(['error' => 'upload error']);
        $ext = strtolower(pathinfo($f['name'], PATHINFO_EXTENSION));
        if ($ext !== 'ipa') json(['error' => 'only .ipa allowed']);
        $id = 'ipa-' . substr(md5($f['name'] . time()), 0, 10) . '.ipa';
        $dest = "$ipadir/$id";
        if (!move_uploaded_file($f['tmp_name'], $dest)) json(['error' => 'move failed']);
        json(['ok' => true, 'ipa' => $id, 'path' => "/storage/ipas/$id"]);
        break;

    // 3) Upload .p12 certificate (multiple allowed)
    case 'upload_p12':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') json(['error' => 'Use POST with multipart']);
        if (!isset($_FILES['file'])) json(['error' => 'file field required']);
        $pw = $_POST['password'] ?? '';
        $f = $_FILES['file'];
        if ($f['error'] !== UPLOAD_ERR_OK) json(['error' => 'upload error']);
        $ext = strtolower(pathinfo($f['name'], PATHINFO_EXTENSION));
        if ($ext !== 'p12' && $ext !== 'pfx') json(['error' => 'only .p12/.pfx allowed']);
        $id = 'p12-' . substr(md5($f['name'] . time()), 0, 10) . '.p12';
        $dest = "$p12dir/$id";
        if (!move_uploaded_file($f['tmp_name'], $dest)) json(['error' => 'move failed']);
        // store meta (do NOT store raw password in production; this is demo)
        $meta = ['id' => $id, 'name' => $f['name'], 'password' => $pw, 'uploaded_at' => time()];
        file_put_contents("$p12dir/$id.json", json_encode($meta, JSON_PRETTY_PRINT));
        json(['ok' => true, 'p12' => $id]);
        break;

    // 4) Upload mobileprovision
    case 'upload_provision':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') json(['error' => 'Use POST with multipart']);
        if (!isset($_FILES['file'])) json(['error' => 'file field required']);
        $f = $_FILES['file'];
        $ext = strtolower(pathinfo($f['name'], PATHINFO_EXTENSION));
        if ($ext !== 'mobileprovision') json(['error' => 'only .mobileprovision allowed']);
        $id = 'prov-' . substr(md5($f['name'] . time()), 0, 10) . '.mobileprovision';
        $dest = "$provdir/$id";
        if (!move_uploaded_file($f['tmp_name'], $dest)) json(['error' => 'move failed']);
        file_put_contents("$provdir/$id.json", json_encode(['id'=>$id,'name'=>$f['name'],'uploaded_at'=>time()], JSON_PRETTY_PRINT));
        json(['ok' => true, 'prov' => $id]);
        break;

    // 5) List uploaded assets
    case 'list_assets':
        $ipas = array_values(array_filter(scandir($ipadir), function($x){return substr($x,-4)=='.ipa';}));
        $p12s = array_values(array_filter(scandir($p12dir), function($x){return substr($x,-4)=='.p12' || substr($x,-4)=='.pfx';}));
        $provs = array_values(array_filter(scandir($provdir), function($x){return substr($x,-15)=='.mobileprovision';}));
        json(['ok'=>true,'ipas'=>$ipas,'p12s'=>$p12s,'provs'=>$provs]);
        break;

    // 6) Create a sign job (this will call a shell script to do the real signing)
    case 'sign':
        // expects POST JSON or form fields:
        // ipa (filename in storage), p12 (filename), prov (filename), display_name (optional), bundle_id (optional), icon_update (base64 or file id)
        $payload = $_POST ? $_POST : json_decode(file_get_contents('php://input'), true);
        if (!$payload) $payload = [];
        $ipa = $payload['ipa'] ?? $_POST['ipa'] ?? null;
        $p12 = $payload['p12'] ?? $_POST['p12'] ?? null;
        $prov = $payload['prov'] ?? $_POST['prov'] ?? null;
        $display = $payload['display_name'] ?? null;
        $bundle = $payload['bundle_id'] ?? null;
        $iconFileId = $payload['icon'] ?? null;

        if (!$ipa || !$p12 || !$prov) json(['error' => 'ipa, p12, prov required']);
        $jobId = 'job-' . substr(md5($ipa.$p12.$prov.time().rand()),0,12);
        $jobDir = "$jobsdir/$jobId";
        mkdir($jobDir, 0775, true);

        // Save job meta
        $meta = [
            'id' => $jobId,
            'ipa' => $ipa,
            'p12' => $p12,
            'prov' => $prov,
            'display_name' => $display,
            'bundle_id' => $bundle,
            'status' => 'queued',
            'created_at' => time()
        ];
        file_put_contents("$jobDir/meta.json", json_encode($meta, JSON_PRETTY_PRINT));

        // Copy needed files into job dir
        copy("$ipadir/$ipa", "$jobDir/orig.ipa");
        copy("$p12dir/$p12", "$jobDir/cert.p12");
        copy("$provdir/$prov", "$jobDir/profile.mobileprovision");

        // optional: icon replace — if icon provided as an uploaded file id (implementation left for frontend).
        // Build command to call signing shell script. The script must exist and be executable.
        $signScript = realpath(__DIR__ . '/../scripts/sign_ipa.sh'); // provided below
        if (!file_exists($signScript)) {
            $meta['status'] = 'error';
            $meta['error'] = 'signing script not found';
            file_put_contents("$jobDir/meta.json", json_encode($meta, JSON_PRETTY_PRINT));
            json(['error' => 'signing script missing on server. Place scripts/sign_ipa.sh and make it executable.']);
        }

        // You may wish to provide a p12 password via meta; for security, avoid plain text in production.
        $p12metaFile = "$p12dir/{$p12}.json";
        $p12pw = '';
        if (file_exists($p12dir . '/' . $p12 . '.json')) {
            $j = json_decode(file_get_contents($p12dir . '/' . $p12 . '.json'), true);
            $p12pw = $j['password'] ?? '';
        } else {
            // attempt to read alternative meta file
            if (file_exists("$p12dir/$p12.json")) {
                $j = json_decode(file_get_contents("$p12dir/$p12.json"), true);
                $p12pw = $j['password'] ?? '';
            }
        }

        // Launch signing (synchronously). In real-world, you'd queue & run async.
        $cmd = escapeshellcmd($signScript) . ' ' . escapeshellarg($jobDir) . ' ' . escapeshellarg($p12pw) . ' 2>&1';
        $meta['status'] = 'running';
        file_put_contents("$jobDir/meta.json", json_encode($meta, JSON_PRETTY_PRINT));

        $output = [];
        $ret = 0;
        exec($cmd, $output, $ret);
        $meta['output'] = $output;
        $meta['exit_code'] = $ret;
        $meta['finished_at'] = time();
        $meta['status'] = $ret === 0 ? 'done' : 'failed';
        file_put_contents("$jobDir/meta.json", json_encode($meta, JSON_PRETTY_PRINT));

        if ($ret === 0) {
            // signed ipa expected at $jobDir/signed.ipa
            $signedPath = "/storage/jobs/$jobId/signed.ipa";
            json(['ok'=>true, 'job'=>$meta, 'signed_url'=>$signedPath]);
        } else {
            json(['error'=>'sign failed','meta'=>$meta]);
        }
        break;

    // 7) Get job status
    case 'job_status':
        $id = $_GET['job'] ?? '';
        if (!$id) json(['error'=>'job id required']);
        if (!is_dir("$jobsdir/$id")) json(['error'=>'job not found']);
        $meta = json_decode(file_get_contents("$jobsdir/$id/meta.json"), true);
        json(['ok'=>true,'meta'=>$meta]);
        break;

    default:
        json(['error'=>'unknown action','usage'=>[
            'ping'=>'?action=ping',
            'register_repo'=>'POST JSON {repo_url,path} -> ?action=register_repo',
            'upload_ipa'=>'POST multipart file -> ?action=upload_ipa',
            'upload_p12'=>'POST multipart file+password -> ?action=upload_p12',
            'upload_provision'=>'POST multipart file -> ?action=upload_provision',
            'list_assets'=>'?action=list_assets',
            'sign'=>'POST -> ?action=sign (ipa,p12,prov,display_name,bundle_id)',
            'job_status'=>'?action=job_status&job=job-xxxxx'
        ]]);
        break;
}
