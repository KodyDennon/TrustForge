{#
   SPDX-License-Identifier: Apache-2.0 OR MIT

   Volt template for the TrustForge plugin UI.
   Sits inside OPNsense's standard chrome (sidebar + header come from
   the app layout). The template renders three Bootstrap tabs:

     - Settings : form bound to OPNsense\Trustforge model
     - Status   : liveness + decision histogram (XHR poll)
     - Bridges  : OAuth / TLS / etc bridge config

   The form helpers (`partial("layout_partials/base_form", …)`) are
   stock OPNsense — they generate Bootstrap form rows from the model
   XML so the UI follows whatever the schema declares.
#}

<script>
$(document).ready(function () {
    // Load form data from the REST API.
    var dataGet = "/api/trustforge/settings/get";
    var dataSet = "/api/trustforge/settings/set";
    var actApply = "/api/trustforge/settings/reconfigure";
    var actStatus= "/api/trustforge/settings/status";

    mapDataToFormUI({
        'frm_general_settings': dataGet,
        'frm_bridges_settings': dataGet
    }).done(function () {
        formatTokenizersUI();
        $('.selectpicker').selectpicker('refresh');
    });

    // Apply = save, then reconfigure.
    $("#btn_apply").click(function () {
        var $btn = $(this);
        $btn.prop("disabled", true);
        saveFormToEndpoint(dataSet, 'frm_general_settings', function () {
            saveFormToEndpoint(dataSet, 'frm_bridges_settings', function () {
                ajaxCall(actApply, {}, function (data) {
                    $btn.prop("disabled", false);
                    refreshStatus();
                });
            });
        });
    });

    function refreshStatus() {
        ajaxGet(actStatus, {}, function (data) {
            if (!data) return;
            $("#tf-running").text(data.running ? "running" : "stopped");
            $("#tf-running").toggleClass("label-success", !!data.running);
            $("#tf-running").toggleClass("label-danger", !data.running);
            $("#tf-profile").text(data.profile || "—");
            $("#tf-actor").text(data.actor   || "—");
            var h = data.histogram || {};
            $("#tf-allow").text(h.allow || 0);
            $("#tf-deny").text(h.deny  || 0);
            $("#tf-ask").text(h.ask   || 0);
        });
    }
    refreshStatus();
    setInterval(refreshStatus, 5000);
});
</script>

<ul class="nav nav-tabs" role="tablist">
    <li class="active"><a data-toggle="tab" href="#settings"  role="tab">{{ lang._('Settings') }}</a></li>
    <li><a data-toggle="tab" href="#bridges"  role="tab">{{ lang._('Bridges') }}</a></li>
    <li><a data-toggle="tab" href="#status"   role="tab">{{ lang._('Status') }}</a></li>
</ul>

<div class="tab-content content-box">

    {# ---- Settings tab ---- #}
    <div id="settings" class="tab-pane fade in active">
        <form id="frm_general_settings">
            {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general_settings']) }}
        </form>
    </div>

    {# ---- Bridges tab ---- #}
    <div id="bridges" class="tab-pane fade">
        <form id="frm_bridges_settings">
            {{ partial("layout_partials/base_form", ['fields': bridgesForm, 'id': 'frm_bridges_settings']) }}
        </form>
    </div>

    {# ---- Status tab ---- #}
    <div id="status" class="tab-pane fade">
        <table class="table table-striped">
            <tbody>
                <tr>
                    <td style="width:25%">{{ lang._('State') }}</td>
                    <td><span id="tf-running" class="label label-default">…</span></td>
                </tr>
                <tr>
                    <td>{{ lang._('Profile') }}</td>
                    <td><code id="tf-profile">—</code></td>
                </tr>
                <tr>
                    <td>{{ lang._('Actor') }}</td>
                    <td><code id="tf-actor">—</code></td>
                </tr>
            </tbody>
        </table>

        <h3>{{ lang._('Decision histogram (last 5 min)') }}</h3>
        <table class="table table-condensed table-bordered" style="width:auto">
            <thead>
                <tr>
                    <th>{{ lang._('Allow') }}</th>
                    <th>{{ lang._('Deny') }}</th>
                    <th>{{ lang._('Ask') }}</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td id="tf-allow">0</td>
                    <td id="tf-deny">0</td>
                    <td id="tf-ask">0</td>
                </tr>
            </tbody>
        </table>
    </div>

</div>

<div class="content-box" style="margin-top:1em; padding:1em;">
    <button id="btn_apply" type="button" class="btn btn-primary">
        <i class="fa fa-save"></i>&nbsp;{{ lang._('Apply') }}
    </button>
    <span class="text-muted" style="margin-left:1em;">
        {{ lang._('Apply re-renders /usr/local/etc/trustforge/config.yaml and reloads the daemon.') }}
    </span>
</div>
