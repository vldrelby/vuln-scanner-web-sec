"use client"

import { useState, useEffect } from "react"
import { useSearchParams } from "next/navigation"
import { Navbar } from "@/components/navbar"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Download, FileText, Loader2 } from "lucide-react"

interface Vulnerability {
  id: number
  title: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  description: string
  affected_url: string
  cve?: string
  recommendation: string
}

interface ScanData {
  id: number
  target_url: string
  scan_type: string
  status: string
  created_at: string
  started_at: string | null
  completed_at: string | null
  vulnerabilities: Vulnerability[]
}

export default function ReportPage() {
  const searchParams = useSearchParams()
  const scanId = searchParams.get('id')
  const [scanData, setScanData] = useState<ScanData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchScanData = async () => {
      if (!scanId) {
        // Try to get the latest scan
        try {
          const response = await fetch('http://localhost:8000/api/scans')
          const data = await response.json()
          if (data.scans && data.scans.length > 0) {
            setScanData(data.scans[0])
          } else {
            setError('No scans found')
          }
        } catch (error) {
          console.error('Error fetching scans:', error)
          setError('Failed to fetch scan data')
        }
        setLoading(false)
        return
      }

      try {
        const response = await fetch(`http://localhost:8000/api/scans/${scanId}`)
        if (!response.ok) {
          throw new Error('Scan not found')
        }
        const data = await response.json()
        setScanData(data)
      } catch (error: any) {
        console.error('Error fetching scan:', error)
        setError(error.message || 'Failed to fetch scan data')
      } finally {
        setLoading(false)
      }
    }

    fetchScanData()
  }, [scanId])

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'N/A'
    const date = new Date(dateString)
    return date.toLocaleDateString("en-US", { 
      year: "numeric", 
      month: "long", 
      day: "numeric" 
    })
  }

  const formatTime = (dateString: string | null) => {
    if (!dateString) return 'N/A'
    const date = new Date(dateString)
    return date.toLocaleTimeString("en-US", { 
      hour: "2-digit", 
      minute: "2-digit" 
    })
  }

  const calculateDuration = () => {
    if (!scanData?.started_at || !scanData?.completed_at) return 'N/A'
    const start = new Date(scanData.started_at)
    const end = new Date(scanData.completed_at)
    const diffMs = end.getTime() - start.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    const diffSecs = Math.floor((diffMs % 60000) / 1000)
    return `${diffMins}m ${diffSecs}s`
  }

  const getScanTypeName = (scanType: string) => {
    const types: Record<string, string> = {
      'nmap': 'Nmap Scan',
      'nuclei': 'Nuclei Scan',
      'custom': 'Custom Scan'
    }
    return types[scanType] || scanType
  }

  const handleExportJSON = () => {
    if (!scanData) return
    
    const exportData = {
      scan: {
        id: scanData.id,
        target_url: scanData.target_url,
        scan_type: scanData.scan_type,
        status: scanData.status,
        created_at: scanData.created_at,
        started_at: scanData.started_at,
        completed_at: scanData.completed_at,
        duration: calculateDuration()
      },
      vulnerabilities: scanData.vulnerabilities,
      summary: {
        total: scanData.vulnerabilities.length,
        critical: scanData.vulnerabilities.filter(v => v.severity === 'critical').length,
        high: scanData.vulnerabilities.filter(v => v.severity === 'high').length,
        medium: scanData.vulnerabilities.filter(v => v.severity === 'medium').length,
        low: scanData.vulnerabilities.filter(v => v.severity === 'low').length,
        info: scanData.vulnerabilities.filter(v => v.severity === 'info').length,
      }
    }

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `scan-${scanData.id}-report.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleExportCSV = () => {
    if (!scanData) return

    const headers = ['ID', 'Title', 'Severity', 'CVE', 'Affected URL', 'Description', 'Recommendation']
    const rows = scanData.vulnerabilities.map(v => [
      v.id.toString(),
      `"${v.title.replace(/"/g, '""')}"`,
      v.severity,
      v.cve || '',
      `"${v.affected_url.replace(/"/g, '""')}"`,
      `"${v.description.replace(/"/g, '""')}"`,
      `"${v.recommendation.replace(/"/g, '""')}"`
    ])

    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.join(','))
    ].join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `scan-${scanData.id}-report.csv`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleExportPDF = () => {
    if (!scanData) return

    // Create PDF content
    const printWindow = window.open('', '_blank')
    if (!printWindow) return

    const vulnerabilitiesList = scanData.vulnerabilities.map(v => `
      <tr>
        <td style="border: 1px solid #ddd; padding: 8px;">${v.id}</td>
        <td style="border: 1px solid #ddd; padding: 8px;">${v.title}</td>
        <td style="border: 1px solid #ddd; padding: 8px;">${v.severity.toUpperCase()}</td>
        <td style="border: 1px solid #ddd; padding: 8px;">${v.cve || 'N/A'}</td>
        <td style="border: 1px solid #ddd; padding: 8px;">${v.affected_url}</td>
      </tr>
    `).join('')

    const pdfContent = `
      <!DOCTYPE html>
      <html>
        <head>
          <title>Security Scan Report - ${scanData.id}</title>
          <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            h1 { color: #333; }
            .summary { margin: 20px 0; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th { background-color: #f2f2f2; font-weight: bold; }
          </style>
        </head>
        <body>
          <h1>Security Scan Report</h1>
          <div class="summary">
            <p><strong>Target URL:</strong> ${scanData.target_url}</p>
            <p><strong>Scan Type:</strong> ${getScanTypeName(scanData.scan_type)}</p>
            <p><strong>Scan Date:</strong> ${formatDate(scanData.created_at)} • ${formatTime(scanData.created_at)}</p>
            <p><strong>Duration:</strong> ${calculateDuration()}</p>
            <p><strong>Total Vulnerabilities:</strong> ${scanData.vulnerabilities.length}</p>
          </div>
          <h2>Vulnerabilities</h2>
          <table>
            <thead>
              <tr>
                <th style="border: 1px solid #ddd; padding: 8px;">ID</th>
                <th style="border: 1px solid #ddd; padding: 8px;">Title</th>
                <th style="border: 1px solid #ddd; padding: 8px;">Severity</th>
                <th style="border: 1px solid #ddd; padding: 8px;">CVE</th>
                <th style="border: 1px solid #ddd; padding: 8px;">Affected URL</th>
              </tr>
            </thead>
            <tbody>
              ${vulnerabilitiesList}
            </tbody>
          </table>
        </body>
      </html>
    `

    printWindow.document.write(pdfContent)
    printWindow.document.close()
    printWindow.print()
  }

  if (loading) {
    return (
      <div className="min-h-screen">
        <Navbar />
        <div className="pt-24 pb-16">
          <div className="container mx-auto px-4">
            <div className="max-w-4xl mx-auto text-center py-12">
              <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4" />
              <p className="text-muted-foreground">Loading scan data...</p>
            </div>
          </div>
        </div>
      </div>
    )
  }

  if (error || !scanData) {
    return (
      <div className="min-h-screen">
        <Navbar />
        <div className="pt-24 pb-16">
          <div className="container mx-auto px-4">
            <div className="max-w-4xl mx-auto text-center py-12">
              <p className="text-destructive">{error || 'Scan not found'}</p>
            </div>
          </div>
        </div>
      </div>
    )
  }

  const vulnerabilities = scanData.vulnerabilities || []
  const stats = {
    total: vulnerabilities.length,
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
    info: vulnerabilities.filter(v => v.severity === 'info').length,
  }

  return (
    <div className="min-h-screen">
      <Navbar />

      <div className="pt-24 pb-16">
        <div className="container mx-auto px-4">
          <div className="max-w-4xl mx-auto">
            {/* Header */}
            <div className="text-center mb-12">
              <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-4">
                <FileText className="h-4 w-4 text-primary" />
                <span className="text-sm font-mono text-primary">Security Report</span>
              </div>
              <h1 className="text-4xl md:text-5xl font-bold mb-4">Export Scan Report</h1>
              <p className="text-muted-foreground text-lg text-pretty leading-relaxed">
                Download or share your comprehensive security analysis report
              </p>
            </div>

            {/* Report Summary */}
            <Card className="p-8 mb-8 bg-card border-border/40">
              <h2 className="text-2xl font-semibold mb-6">Report Summary</h2>

              <div className="grid md:grid-cols-2 gap-6">
                <div>
                  <div className="text-sm text-muted-foreground mb-1">Target URL</div>
                  <div className="font-mono text-sm bg-secondary px-3 py-2 rounded break-all">{scanData.target_url}</div>
                </div>
                <div>
                  <div className="text-sm text-muted-foreground mb-1">Scan Type</div>
                  <div className="font-semibold">{getScanTypeName(scanData.scan_type)}</div>
                </div>
                <div>
                  <div className="text-sm text-muted-foreground mb-1">Scan Date & Time</div>
                  <div className="font-semibold">
                    {formatDate(scanData.created_at)} • {formatTime(scanData.created_at)}
                  </div>
                </div>
                <div>
                  <div className="text-sm text-muted-foreground mb-1">Duration</div>
                  <div className="font-mono font-semibold">{calculateDuration()}</div>
                </div>
              </div>

              <div className="mt-6 pt-6 border-t border-border">
                <div className="text-sm text-muted-foreground mb-3">Vulnerabilities Detected</div>
                <div className="flex flex-wrap gap-3">
                  <div className="px-4 py-2 bg-destructive/10 border border-destructive/20 rounded-lg">
                    <span className="font-bold text-xl">{stats.critical}</span>
                    <span className="text-sm text-muted-foreground ml-2">Critical</span>
                  </div>
                  <div className="px-4 py-2 bg-warning/10 border border-warning/20 rounded-lg">
                    <span className="font-bold text-xl">{stats.high}</span>
                    <span className="text-sm text-muted-foreground ml-2">High</span>
                  </div>
                  <div className="px-4 py-2 bg-chart-3/10 border border-chart-3/20 rounded-lg">
                    <span className="font-bold text-xl">{stats.medium}</span>
                    <span className="text-sm text-muted-foreground ml-2">Medium</span>
                  </div>
                  <div className="px-4 py-2 bg-accent/10 border border-accent/20 rounded-lg">
                    <span className="font-bold text-xl">{stats.low}</span>
                    <span className="text-sm text-muted-foreground ml-2">Low</span>
                  </div>
                  {stats.info > 0 && (
                    <div className="px-4 py-2 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                      <span className="font-bold text-xl">{stats.info}</span>
                      <span className="text-sm text-muted-foreground ml-2">Info</span>
                    </div>
                  )}
                </div>
              </div>
            </Card>

            {/* Export Options */}
            <Card className="p-8 mb-8 bg-card border-border/40">
              <h2 className="text-2xl font-semibold mb-6">Export Options</h2>

              <div className="grid md:grid-cols-3 gap-4">
                <button
                  onClick={handleExportPDF}
                  className="p-6 rounded-lg border-2 border-border/40 hover:border-primary hover:bg-primary/5 transition-all text-left cursor-pointer"
                >
                  <Download className="h-8 w-8 text-primary mb-3" />
                  <div className="font-semibold mb-1">PDF Report</div>
                  <div className="text-sm text-muted-foreground">Formatted document ready for sharing</div>
                </button>

                <button
                  onClick={handleExportJSON}
                  className="p-6 rounded-lg border-2 border-border/40 hover:border-primary hover:bg-primary/5 transition-all text-left cursor-pointer"
                >
                  <FileText className="h-8 w-8 text-primary mb-3" />
                  <div className="font-semibold mb-1">JSON Data</div>
                  <div className="text-sm text-muted-foreground">Raw data for integration</div>
                </button>

                <button
                  onClick={handleExportCSV}
                  className="p-6 rounded-lg border-2 border-border/40 hover:border-primary hover:bg-primary/5 transition-all text-left cursor-pointer"
                >
                  <FileText className="h-8 w-8 text-primary mb-3" />
                  <div className="font-semibold mb-1">CSV File</div>
                  <div className="text-sm text-muted-foreground">Spreadsheet-compatible format</div>
                </button>
              </div>
            </Card>
          </div>
        </div>
      </div>
    </div>
  )
}
