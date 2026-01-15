"use client"

import { useState, useEffect, useRef } from "react"
import { useSearchParams } from "next/navigation"
import Link from "next/link"
import { Navbar } from "@/components/navbar"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { AlertTriangle, Info, XCircle, CheckCircle, FileText, ExternalLink, Loader2 } from "lucide-react"

type Severity = "critical" | "high" | "medium" | "low" | "info"

interface Vulnerability {
  id: number
  title: string
  severity: Severity
  cve?: string
  description: string
  affected_url: string
  recommendation: string
}

export default function ResultsPage() {
  const searchParams = useSearchParams()
  const scanId = searchParams.get('id')
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([])
  const [loading, setLoading] = useState(true)
  const [scanStatus, setScanStatus] = useState<string>('loading')
  const [error, setError] = useState<string | null>(null)

  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null)
  const retryCountRef = useRef(0)
  const maxRetries = 5
  
  const fetchScanResults = async () => {
      if (!scanId) {
        // Try to get the latest scan
        try {
          const response = await fetch('http://localhost:8000/api/scans')
          const data = await response.json()
          if (data.scans && data.scans.length > 0) {
            const latestScan = data.scans[0]
            setVulnerabilities(latestScan.vulnerabilities || [])
            setScanStatus(latestScan.status)
          }
        } catch (error) {
          console.error('Error fetching scans:', error)
        }
        setLoading(false)
        return
      }

      try {
        const response = await fetch(`http://localhost:8000/api/scans/${scanId}`)
        
        if (!response.ok) {
          if (response.status === 404) {
            // Scan not found - might still be creating, retry a few times
            if (retryCountRef.current < maxRetries) {
              retryCountRef.current++
              console.log(`Scan ${scanId} not found, retrying... (${retryCountRef.current}/${maxRetries})`)
              setTimeout(() => {
                fetchScanResults()
              }, 1000)
              return
            } else {
              // Max retries reached, show error
              setScanStatus('failed')
              setError(`Scan with ID ${scanId} not found. It may have been deleted or never created.`)
              setLoading(false)
              return
            }
          }
          
          // Other HTTP errors
          const errorData = await response.json().catch(() => ({}))
          throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`)
        }
        
        // Reset retry count on success
        retryCountRef.current = 0
        setError(null) // Clear any previous errors
        
        const scan = await response.json()
        setScanStatus(scan.status)
        setVulnerabilities(scan.vulnerabilities || [])
        
        // If scan is still running, poll for updates more frequently
        if (scan.status === 'running' || scan.status === 'pending') {
          setLoading(false) // Show results even while scanning
          if (!pollIntervalRef.current) {
            // Poll every 1 second for real-time updates (especially for nuclei)
            pollIntervalRef.current = setInterval(() => {
              fetchScanResults()
            }, 1000)
          }
        } else {
          if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current)
            pollIntervalRef.current = null
          }
          setLoading(false)
        }
      } catch (error: any) {
        console.error('Error fetching scan:', error)
        setScanStatus('failed')
        setError(error.message || 'Failed to fetch scan results. Please check if the backend is running.')
        setLoading(false)
        if (pollIntervalRef.current) {
          clearInterval(pollIntervalRef.current)
          pollIntervalRef.current = null
        }
      }
    }
  
  useEffect(() => {
    fetchScanResults()
    
    // Cleanup interval on unmount
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current)
        pollIntervalRef.current = null
      }
      retryCountRef.current = 0
    }
  }, [scanId])

  const severityConfig = {
    critical: {
      icon: XCircle,
      color: "text-destructive",
      bg: "bg-destructive/10",
      border: "border-destructive/20",
      label: "Critical",
    },
    high: {
      icon: AlertTriangle,
      color: "text-warning",
      bg: "bg-warning/10",
      border: "border-warning/20",
      label: "High",
    },
    medium: {
      icon: Info,
      color: "text-chart-3",
      bg: "bg-chart-3/10",
      border: "border-chart-3/20",
      label: "Medium",
    },
    low: {
      icon: CheckCircle,
      color: "text-accent",
      bg: "bg-accent/10",
      border: "border-accent/20",
      label: "Low",
    },
    info: {
      icon: Info,
      color: "text-blue-500",
      bg: "bg-blue-500/10",
      border: "border-blue-500/20",
      label: "Info",
    },
  }

  const stats = {
    critical: vulnerabilities.filter((v) => v.severity === "critical").length,
    high: vulnerabilities.filter((v) => v.severity === "high").length,
    medium: vulnerabilities.filter((v) => v.severity === "medium").length,
    low: vulnerabilities.filter((v) => v.severity === "low").length,
    info: vulnerabilities.filter((v) => v.severity === "info").length,
  }

  return (
    <div className="min-h-screen">
      <Navbar />

      <div className="pt-24 pb-16">
        <div className="container mx-auto px-4">
          <div className="max-w-6xl mx-auto">
            {/* Header */}
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-8">
              <div>
                <h1 className="text-4xl font-bold mb-2">Scan Results</h1>
                {loading ? (
                  <p className="text-muted-foreground flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Loading scan results...
                  </p>
                ) : scanStatus === 'running' || scanStatus === 'pending' ? (
                  <p className="text-muted-foreground flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Scan in progress... • {vulnerabilities.length} {vulnerabilities.length === 1 ? 'vulnerability' : 'vulnerabilities'} found so far
                  </p>
                ) : scanStatus === 'failed' ? (
                  <p className="text-destructive flex items-center gap-2">
                    <XCircle className="h-4 w-4" />
                    Scan failed
                  </p>
                ) : (
                  <p className="text-muted-foreground flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    Scan completed • {vulnerabilities.length} {vulnerabilities.length === 1 ? 'vulnerability' : 'vulnerabilities'} found
                  </p>
                )}
              </div>
              <Button asChild className="gap-2">
                <Link href="/report">
                  <FileText className="h-4 w-4" />
                  Generate Report
                </Link>
              </Button>
            </div>

            {/* Error Message */}
            {error && (
              <Card className="p-4 bg-destructive/10 border-destructive/20 mb-8">
                <div className="flex items-start gap-3">
                  <XCircle className="h-5 w-5 text-destructive mt-0.5 flex-shrink-0" />
                  <div className="flex-1">
                    <div className="font-semibold text-destructive mb-1">Error</div>
                    <div className="text-sm text-destructive/90">{error}</div>
                    {scanId && (
                      <div className="mt-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            setError(null)
                            retryCountRef.current = 0
                            fetchScanResults()
                          }}
                          className="mt-2"
                        >
                          Retry
                        </Button>
                      </div>
                    )}
                  </div>
                </div>
              </Card>
            )}

            {/* Stats Cards */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
              {(["critical", "high", "medium", "low", "info"] as const).map((severity) => {
                const config = severityConfig[severity]
                const Icon = config.icon
                return (
                  <Card key={severity} className={`p-4 border-2 ${config.border}`}>
                    <div className="flex items-center gap-3 mb-2">
                      <div className={`rounded-md ${config.bg} p-2`}>
                        <Icon className={`h-4 w-4 ${config.color}`} />
                      </div>
                      <span className="text-2xl font-bold font-mono">{stats[severity]}</span>
                    </div>
                    <div className="text-sm text-muted-foreground capitalize">{config.label}</div>
                  </Card>
                )
              })}
            </div>

            {/* Vulnerabilities List */}
            <div className="space-y-4">
              <h2 className="text-2xl font-semibold mb-4">Detected Vulnerabilities</h2>
              {loading ? (
                <div className="text-center py-12">
                  <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4" />
                  <p className="text-muted-foreground">Loading vulnerabilities...</p>
                </div>
              ) : (scanStatus === 'running' || scanStatus === 'pending') && vulnerabilities.length === 0 ? (
                <Card className="p-8 text-center">
                  <Loader2 className="h-12 w-12 mx-auto mb-4 animate-spin text-primary" />
                  <h3 className="text-xl font-semibold mb-2">Scan in Progress</h3>
                  <p className="text-muted-foreground">
                    Scanning target for vulnerabilities... Results will appear here as they are discovered.
                  </p>
                </Card>
              ) : vulnerabilities.length === 0 ? (
                <Card className="p-8 text-center">
                  <CheckCircle className="h-12 w-12 mx-auto mb-4 text-green-500" />
                  <h3 className="text-xl font-semibold mb-2">No Vulnerabilities Found</h3>
                  <p className="text-muted-foreground">The scan completed successfully and no security issues were detected.</p>
                </Card>
              ) : (
                vulnerabilities.map((vuln) => {
                const config = severityConfig[vuln.severity]
                const Icon = config.icon
                return (
                  <Card key={vuln.id} className="p-6 border-border/40 hover:border-border transition-all">
                    <div className="flex flex-col md:flex-row md:items-start gap-4">
                      <div className={`rounded-lg ${config.bg} p-3`}>
                        <Icon className={`h-6 w-6 ${config.color}`} />
                      </div>

                      <div className="flex-1 space-y-3">
                        <div className="flex flex-wrap items-start gap-3">
                          <h3 className="text-xl font-semibold flex-1">{vuln.title}</h3>
                          <div className="flex gap-2">
                            <Badge variant="outline" className={`${config.color} ${config.border} capitalize`}>
                              {config.label}
                            </Badge>
                            {vuln.cve && (
                              <Badge variant="secondary" className="font-mono">
                                {vuln.cve}
                              </Badge>
                            )}
                          </div>
                        </div>

                        <p className="text-muted-foreground leading-relaxed">{vuln.description}</p>

                        <div className="grid md:grid-cols-2 gap-4 pt-2">
                          <div>
                            <div className="text-sm font-semibold mb-1">Affected Component</div>
                            <code className="text-sm bg-secondary px-2 py-1 rounded font-mono break-all">{vuln.affected_url}</code>
                            {vuln.evidence && (
                              <div className="mt-2 space-y-1">
                                {vuln.evidence.port && (
                                  <div className="text-xs text-muted-foreground">
                                    Port: {vuln.evidence.port}/{vuln.evidence.protocol || 'tcp'}
                                  </div>
                                )}
                                {vuln.evidence.service && (
                                  <div className="text-xs text-muted-foreground">
                                    Service: {vuln.evidence.service}
                                  </div>
                                )}
                                {vuln.evidence.version && (
                                  <div className="text-xs text-muted-foreground">
                                    Version: {vuln.evidence.version}
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                          <div>
                            <div className="text-sm font-semibold mb-1">Recommendation</div>
                            <p className="text-sm text-muted-foreground leading-relaxed">{vuln.recommendation}</p>
                          </div>
                        </div>

                        {vuln.cve && (
                          <Button variant="ghost" size="sm" className="gap-2 text-primary hover:text-primary" asChild>
                            <a
                              href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.cve}`}
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              View CVE Details
                              <ExternalLink className="h-3 w-3" />
                            </a>
                          </Button>
                        )}
                      </div>
                    </div>
                  </Card>
                )
              })
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
