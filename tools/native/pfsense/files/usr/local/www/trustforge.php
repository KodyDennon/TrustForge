<?php
/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * pfSense web UI for TrustForge.
 *
 * Renders inside pfSense's Bootstrap chrome (header/footer come from
 * /usr/local/www/head.inc + foot.inc). The page is tabbed:
 *
 *   - Configuration  : edit /usr/local/etc/trustforge/config.yaml fields
 *   - Status         : daemon liveness, profile, decision histogram
 *   - Logs           : tail of /var/log/trustforge/trustforge.log
 *
 * The PHP layer never speaks the TrustForge protocol directly — it
 * shells out to `tf-daemon ctl …` and reads the rc.subr-managed
 * service status. This keeps the web UI dependency-free from the
 * daemon's wire format.
 */

require_once("guiconfig.inc");
require_once("util.inc");
require_once("pfsense-utils.inc");

$pgtitle    = array(gettext("Services"), gettext("TrustForge"));
$pglinks    = array("", "@self");
$shortcut_section = "trustforge";

$tab = isset($_GET['tab']) ? $_GET['tab'] : 'config';
if (!in_array($tab, array('config', 'status', 'logs'), true)) {
    $tab = 'config';
}

$conffile = "/usr/local/etc/trustforge/config.yaml";
$logfile  = "/var/log/trustforge/trustforge.log";

// ---- POST handler ---------------------------------------------------
$savemsg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $tab === 'config') {
    $body = trim($_POST['config_yaml'] ?? '');
    if ($body === '') {
        $input_errors[] = gettext("Configuration cannot be empty.");
    }
    if (empty($input_errors)) {
        // Atomic write: stage to a tmp file, fsync, then rename.
        $tmp = $conffile . ".tmp";
        if (file_put_contents($tmp, $body) === false ||
            !rename($tmp, $conffile)) {
            $input_errors[] = gettext("Failed to write configuration.");
        } else {
            mwexec("/usr/sbin/service trustforge reload");
            $savemsg = gettext("Configuration saved and tf-daemon reloaded.");
        }
    }
}

// ---- helpers --------------------------------------------------------
function tf_service_status() {
    exec("/usr/sbin/service trustforge status 2>&1", $out, $rc);
    return array('running' => ($rc === 0), 'output' => implode("\n", $out));
}

function tf_ctl($verb) {
    $out = array();
    exec("/usr/local/bin/tf-daemon ctl " . escapeshellarg($verb) . " 2>/dev/null", $out, $rc);
    if ($rc !== 0 || empty($out)) {
        return null;
    }
    return json_decode(implode("\n", $out), true);
}

include("head.inc");

if (!empty($input_errors)) print_input_errors($input_errors);
if ($savemsg)              print_info_box($savemsg, 'success');
?>

<ul class="nav nav-tabs">
    <li class="<?= $tab === 'config' ? 'active' : '' ?>">
        <a href="?tab=config"><?= gettext("Configuration") ?></a>
    </li>
    <li class="<?= $tab === 'status' ? 'active' : '' ?>">
        <a href="?tab=status"><?= gettext("Status") ?></a>
    </li>
    <li class="<?= $tab === 'logs' ? 'active' : '' ?>">
        <a href="?tab=logs"><?= gettext("Logs") ?></a>
    </li>
</ul>

<div class="tab-content">

<?php if ($tab === 'config'): ?>
    <div class="panel panel-default">
        <div class="panel-heading"><h2 class="panel-title"><?= gettext("Daemon configuration") ?></h2></div>
        <div class="panel-body">
            <form method="post" action="?tab=config">
                <p class="text-muted">
                    <?= gettext("Edits this file in place: ") ?><code><?= htmlspecialchars($conffile) ?></code>.
                    <?= gettext("Saving sends SIGHUP to tf-daemon (live sessions are preserved).") ?>
                </p>
                <textarea name="config_yaml" rows="22" class="form-control" style="font-family:monospace;"><?php
                    echo htmlspecialchars(@file_get_contents($conffile) ?: '');
                ?></textarea>
                <br>
                <button type="submit" class="btn btn-primary">
                    <i class="fa fa-save"></i> <?= gettext("Save") ?>
                </button>
            </form>
        </div>
    </div>

<?php elseif ($tab === 'status'): ?>
    <?php
    $svc        = tf_service_status();
    $status     = tf_ctl('status')              ?: array();
    $histogram  = tf_ctl('decision_histogram')  ?: array('allow'=>0,'deny'=>0,'ask'=>0);
    ?>
    <div class="panel panel-default">
        <div class="panel-heading"><h2 class="panel-title"><?= gettext("Daemon status") ?></h2></div>
        <div class="panel-body">
            <p>
                <strong><?= $svc['running'] ? gettext("Running") : gettext("Stopped") ?></strong>
                <?php if (!empty($status['profile'])): ?>
                    — <?= gettext("profile") ?> <code><?= htmlspecialchars($status['profile']) ?></code>
                <?php endif; ?>
                <?php if (!empty($status['actor'])): ?>
                    — <?= gettext("actor") ?> <code><?= htmlspecialchars($status['actor']) ?></code>
                <?php endif; ?>
            </p>
            <pre><?= htmlspecialchars($svc['output']) ?></pre>
        </div>
    </div>

    <div class="panel panel-default">
        <div class="panel-heading"><h2 class="panel-title"><?= gettext("Decision histogram (last 5 min)") ?></h2></div>
        <div class="panel-body">
            <table class="table table-striped table-condensed">
                <thead><tr><th><?= gettext("Allow") ?></th><th><?= gettext("Deny") ?></th><th><?= gettext("Ask") ?></th></tr></thead>
                <tbody><tr>
                    <td><?= (int)($histogram['allow'] ?? 0) ?></td>
                    <td><?= (int)($histogram['deny']  ?? 0) ?></td>
                    <td><?= (int)($histogram['ask']   ?? 0) ?></td>
                </tr></tbody>
            </table>
        </div>
    </div>

<?php elseif ($tab === 'logs'): ?>
    <div class="panel panel-default">
        <div class="panel-heading"><h2 class="panel-title"><?= gettext("Recent log lines") ?></h2></div>
        <div class="panel-body">
            <pre style="max-height:480px; overflow:auto;"><?php
                if (is_readable($logfile)) {
                    $tail = shell_exec("/usr/bin/tail -n 200 " . escapeshellarg($logfile));
                    echo htmlspecialchars($tail ?? '');
                } else {
                    echo htmlspecialchars(sprintf(gettext("Log file %s is not readable."), $logfile));
                }
            ?></pre>
        </div>
    </div>
<?php endif; ?>

</div><!-- /.tab-content -->

<?php include("foot.inc"); ?>
