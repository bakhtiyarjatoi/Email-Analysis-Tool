function checkEmailHeaders() {
    const headersText = document.getElementById('emailHeaders').value;
    
    if (!headersText) {
        alert('Please paste email headers.');
        return;
    }

    // Split headers into individual lines
    const headersLines = headersText.split('\n');
    const headersList = document.getElementById('headers-list');
    headersList.innerHTML = ''; // Clear any previous results

    headersLines.forEach(line => {
        if (line.trim()) {
            const listItem = document.createElement('li');
            listItem.textContent = line;
            headersList.appendChild(listItem);
        }
    });

    // Show the headers section
    document.querySelector('.headers-section').style.display = 'block';
}

// Function to export data to CSV
function exportToCSV() {
    const headers = [];
    const rows = [];
    
    // Extract headers from the tables (email headers, IOCs, and VirusTotal results)
    const headerRows = document.querySelectorAll('.results-table thead tr');
    headerRows.forEach(row => {
        row.querySelectorAll('th').forEach(th => {
            headers.push(th.textContent.trim());
        });
    });

    // Extract data from the tables (email headers, IOCs, and VirusTotal results)
    const dataRows = document.querySelectorAll('.results-table tbody tr');
    dataRows.forEach(row => {
        const rowData = [];
        row.querySelectorAll('td').forEach(td => {
            rowData.push(td.textContent.trim());
        });
        rows.push(rowData);
    });

    // Create the CSV content
    let csvContent = headers.join(",") + "\n";
    rows.forEach(row => {
        csvContent += row.join(",") + "\n";
    });

    // Create a downloadable link for the CSV file
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.setAttribute('href', URL.createObjectURL(blob));
    link.setAttribute('download', 'email_analysis_results.csv');
    link.click();
}

function exportToHTML() {
    let htmlContent = `
        <html>
        <head>
            <title>Email Analysis Results</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background-color: #f9f9f9; color: #333; }
                h1, h2 { color: #444; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                table, th, td { border: 1px solid #ddd; }
                th, td { padding: 8px; text-align: left; font-size: 14px; }
                th { background-color: #f1f1f1; color: #333; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                tr:hover { background-color: #f1f1f1; }
                .result-block { margin-bottom: 20px; padding: 10px; background-color: #fff; border: 1px solid #ddd; border-radius: 4px; }
                .result-block h3 { margin: 0 0 10px; color: #444; font-size: 16px; }
                pre { font-size: 13px; background-color: #f4f4f4; padding: 10px; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word; }
            </style>
        </head>
        <body>
            <h1>Email Analysis Results</h1>
    `;

    const sections = [
        { selector: '.headers-section .results-table tbody tr', title: "Email Headers", columns: ["Header", "Value"] },
        { selector: '.iocs-section .results-table tbody tr', title: "Extracted IOCs", columns: ["Type", "Values"] },
        { selector: '.spf-dmarc-dkim-section .results-table tbody tr', title: "SPF, DMARC, DKIM Results", columns: ["Check", "Result"] }
    ];

    sections.forEach(section => {
        const rows = document.querySelectorAll(section.selector);
        if (rows.length > 0) {
            htmlContent += `<h2>${section.title}</h2><table><thead><tr>`;
            section.columns.forEach(col => { htmlContent += `<th>${col}</th>`; });
            htmlContent += "</tr></thead><tbody>";

            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                htmlContent += "<tr>";
                cells.forEach(cell => { htmlContent += `<td>${cell.textContent.trim()}</td>`; });
                htmlContent += "</tr>";
            });

            htmlContent += "</tbody></table>";
        }
    });

    // Export VirusTotal section
    const vtResults = document.querySelectorAll('.virustotal-section .result-block');
    if (vtResults.length > 0) {
        htmlContent += "<h2>VirusTotal Results</h2>";
        vtResults.forEach(block => {
            htmlContent += `<div class='result-block'>${block.innerHTML}</div>`;
        });
    }

    htmlContent += "</body></html>";

    // Create downloadable link for HTML
    const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'email_analysis_results.html';
    link.click();
}
