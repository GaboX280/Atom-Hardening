import datetime
import html
import os


class HTMLReporter:
    @staticmethod
    def save(summary: dict, findings: list):

        folder = HTMLReporter._get_report_folder()

        filename = HTMLReporter._generate_filename(folder)

        content = HTMLReporter._build_html(summary, findings)

        with open(filename, "w", encoding="utf-8") as file:
            file.write(content)

        return filename

    # ==================================
    # RUTA
    # ==================================

    @staticmethod
    def _get_report_folder():

        home = os.path.expanduser("~")

        folder = os.path.join(home, "Desktop", "Atom Logs")

        os.makedirs(folder, exist_ok=True)

        return folder

    @staticmethod
    def _generate_filename(folder):

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        return os.path.join(folder, f"reporte_atom_{timestamp}.html")

    # ==================================
    # CONSTRUCTOR DE HTML
    # ==================================

    @staticmethod
    def _build_html(summary, findings):

        score = summary.get("score", 0)

        rating = summary.get("rating", "UNKNOWN")

        rows = ""

        for finding in findings:
            status = finding.status.upper()

            if status == "PASS":
                color = "#22c55e"

            elif status == "WARNING":
                color = "#eab308"

            else:
                color = "#ef4444"

            rows += f"""

            <tr>

                <td>{html.escape(finding.title)}</td>

                <td style="color:{color}">
                    {status}
                </td>

                <td>
                    {finding.severity}
                </td>

                <td>
                    {finding.category}
                </td>


                <td>
                    {html.escape(finding.details)}
                </td>


                <td>
                    {html.escape(finding.recommendation)}
                </td>


            </tr>

            """

        return f"""

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">


<title>
Atom Security Report
</title>


<style>


body {{

    background:#0f172a;

    color:white;

    font-family:
    Arial, sans-serif;

    padding:40px;

}}



.container {{

    max-width:1200px;

    margin:auto;

}}



.header {{

    text-align:center;

}}



.score {{

    font-size:50px;

    font-weight:bold;

}}



.card {{

    background:#1e293b;

    padding:20px;

    border-radius:10px;

    margin-top:20px;

}}



table {{

    width:100%;

    border-collapse:collapse;

}}



th {{

    background:#334155;

    padding:12px;

}}



td {{

    padding:12px;

    border-bottom:1px solid #475569;

}}



</style>


</head>


<body>


<div class="container">



<div class="header">


<h1>
ATOM SECURITY REPORT
</h1>


<p>
Generated:
{datetime.datetime.now()}
</p>


<div class="score">

{score}/100

</div>


<h2>

{rating}

</h2>


</div>




<div class="card">


<h2>
Summary
</h2>


<p>
Total Findings:
{summary.get("total", 0)}
</p>


<p>
PASS:
{summary.get("status", {}).get("PASS", 0)}

</p>


<p>
WARNING:
{summary.get("status", {}).get("WARNING", 0)}

</p>


<p>
FAIL:
{summary.get("status", {}).get("FAIL", 0)}

</p>



</div>




<div class="card">


<h2>
Findings
</h2>



<table>


<tr>

<th>
Title
</th>

<th>
Status
</th>

<th>
Severity
</th>

<th>
Category
</th>

<th>
Details
</th>

<th>
Recommendation
</th>


</tr>


{rows}


</table>


</div>


</div>


</body>


</html>

"""
