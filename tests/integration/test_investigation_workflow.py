import asyncio
import json

import httpx

from threat_detector.api.app import create_app
from threat_detector.cli import main
from threat_detector.investigation.service import get_finding_view
from threat_detector.persistence.repository import list_findings, load_finding
from threat_detector.persistence.schema import connect


def test_linux_ssh_finding_is_persisted_reconstructed_and_exposed_by_api(
    tmp_path, capsys
):
    input_path = tmp_path / "ssh-attack.log"
    database_path = tmp_path / "investigations.sqlite3"
    failed_logins = [
        f"Jan  1 00:00:{second:02d} host sshd[1001]: Failed password for alice "
        "from 203.0.113.50 port 2222"
        for second in (0, 10, 20, 30, 40)
    ]
    successful_login = (
        "Jan  1 00:00:50 host sshd[1006]: Accepted password for root "
        "from 203.0.113.50 port 2222"
    )
    input_path.write_text(
        "\n".join([*failed_logins, successful_login]), encoding="utf-8"
    )

    assert main(
        [
            "--input",
            str(input_path),
            "--format",
            "linux-auth",
            "--reference-time",
            "2026-09-02T12:00:00+00:00",
            "--output",
            "json",
            "--database",
            str(database_path),
        ]
    ) == 0

    reported_alerts = json.loads(capsys.readouterr().out)
    assert [alert["rule_id"] for alert in reported_alerts] == ["ssh_brute_force"]

    connection = connect(str(database_path))
    try:
        summaries = list_findings(connection)
        assert len(summaries) == 1
        finding_pk = summaries[0].finding_pk
        finding = load_finding(connection, finding_pk)
        view = get_finding_view(connection, finding_pk)

        assert finding.finding_type == "credential_attack_success"
        assert finding.severity == "critical"
        assert finding.source_ip == "203.0.113.50"
        assert finding.username == "root"
        assert len(finding.contributing_alerts) == 1
        assert finding.contributing_alerts[0].rule_id == "ssh_brute_force"
        assert len(finding.contributing_events) == 1
        assert finding.contributing_events[0].event_type == "authentication_success"
        assert finding.contributing_events[0].username == "root"
        assert view.finding_id == finding.finding_id
        assert [entry.kind for entry in view.timeline.entries] == ["alert", "event"]

        alert_positions = connection.execute(
            "SELECT position FROM finding_alerts WHERE finding_pk = ? "
            "ORDER BY position",
            (finding_pk,),
        ).fetchall()
        event_positions = connection.execute(
            "SELECT position FROM finding_events WHERE finding_pk = ? "
            "ORDER BY position",
            (finding_pk,),
        ).fetchall()
        assert [row["position"] for row in alert_positions] == [0]
        assert [row["position"] for row in event_positions] == [0]
    finally:
        connection.close()

    async def read_api():
        application = create_app(database_path)
        async with application.router.lifespan_context(application):
            transport = httpx.ASGITransport(app=application)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                page = await client.get("/findings")
                detail = await client.get(f"/findings/{finding_pk}")
                return page, detail

    page_response, detail_response = asyncio.run(read_api())
    assert page_response.status_code == 200
    assert page_response.json()["items"][0]["id"] == finding_pk
    assert detail_response.status_code == 200
    assert detail_response.json()["finding_type"] == "credential_attack_success"
    assert detail_response.json()["entities"][0]["value"] == "203.0.113.50"