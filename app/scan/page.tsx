"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { Navbar } from "@/components/navbar"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Loader2, Play, Terminal, Zap, FileCode } from "lucide-react"

type ScanType = "nmap" | "nuclei" | "custom"

export default function ScanPage() {
  const router = useRouter()
  const [url, setUrl] = useState("")
  const [selectedScan, setSelectedScan] = useState<ScanType>("custom")
  const [isScanning, setIsScanning] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const scanTypes = [
    {
      id: "nmap" as const,
      name: "Nmap Scan",
      icon: Terminal,
      description: "Network discovery and port scanning",
      duration: "~3-5 minutes",
    },
    {
      id: "nuclei" as const,
      name: "Nuclei Scan",
      icon: Zap,
      description: "Fast vulnerability detection (medium/high/critical severity)",
      duration: "~2-5 minutes",
    },
    {
      id: "custom" as const,
      name: "Custom Scan",
      icon: FileCode,
      description: "Comprehensive application security checks (headers, XSS, SQLi, cookies, CORS, sensitive files)",
      duration: "~2-3 minutes",
    },
  ]

  const handleScan = async () => {
    if (!url) {
      setError('Please enter a target URL')
      return
    }

    // Validate URL format
    try {
      new URL(url)
    } catch {
      setError('Please enter a valid URL (e.g., https://example.com)')
      return
    }

    setIsScanning(true)
    setError(null)

    try {
      // Create scan via API
      const response = await fetch('http://localhost:8000/api/scans', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target_url: url,
          scan_type: selectedScan
        }),
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.detail || `Failed to start scan: ${response.statusText}`)
      }

      const scan = await response.json()
      
      // Redirect to results page immediately to show progress
      router.push(`/results?id=${scan.id}`)
      
    } catch (error: any) {
      console.error('Scan error:', error)
      setIsScanning(false)
      setError(error.message || 'Failed to start scan. Please check if the backend is running.')
    }
  }

  return (
    <div className="min-h-screen">
      <Navbar />

      <div className="pt-24 pb-16">
        <div className="container mx-auto px-4">
          <div className="max-w-4xl mx-auto">
            {/* Header */}
            <div className="text-center mb-12">
              <h1 className="text-4xl md:text-5xl font-bold mb-4">Launch Security Scan</h1>
              <p className="text-muted-foreground text-lg text-pretty leading-relaxed">
                Enter a target URL and select your preferred scanning method
              </p>
            </div>

            {/* Scan Configuration */}
            <Card className="p-8 mb-8 bg-card border-border/40">
              <div className="space-y-6">
                {/* URL Input */}
                <div className="space-y-2">
                  <Label htmlFor="url" className="text-base">
                    Target URL
                  </Label>
                  <Input
                    id="url"
                    type="url"
                    placeholder="https://example.com"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    className="h-12 text-base font-mono bg-secondary/50 border-border/60"
                    disabled={isScanning}
                  />
                </div>

                {/* Scan Type Selection */}
                <div className="space-y-3">
                  <Label className="text-base">Scan Type</Label>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {scanTypes.map((scan) => {
                      const Icon = scan.icon
                      const isSelected = selectedScan === scan.id
                      return (
                        <button
                          key={scan.id}
                          onClick={() => !isScanning && setSelectedScan(scan.id)}
                          className={`p-4 rounded-lg border-2 text-left transition-all ${
                            isSelected
                              ? "border-primary bg-primary/5"
                              : "border-border/40 hover:border-border hover:bg-secondary/30"
                          } ${isScanning ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
                          disabled={isScanning}
                        >
                          <div className="flex items-start gap-3 mb-3">
                            <div className={`rounded-md p-2 ${isSelected ? "bg-primary/20" : "bg-secondary"}`}>
                              <Icon className={`h-5 w-5 ${isSelected ? "text-primary" : "text-muted-foreground"}`} />
                            </div>
                            <div className="flex-1">
                              <div
                                className={`font-semibold mb-1 ${isSelected ? "text-foreground" : "text-foreground"}`}
                              >
                                {scan.name}
                              </div>
                              <div className="text-xs text-muted-foreground">{scan.duration}</div>
                            </div>
                          </div>
                          <p className="text-sm text-muted-foreground leading-relaxed">{scan.description}</p>
                        </button>
                      )
                    })}
                  </div>
                </div>
              </div>
            </Card>

            {/* Error Message */}
            {error && (
              <Card className="p-4 bg-destructive/10 border-destructive/20">
                <div className="text-sm text-destructive">{error}</div>
              </Card>
            )}

            {/* Action Button */}
            <div className="flex flex-col items-center gap-4">
              <Button
                size="lg"
                onClick={handleScan}
                disabled={!url || isScanning}
                className="w-full md:w-auto px-8 gap-2 font-semibold"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="h-5 w-5 animate-spin" />
                    Starting Scan...
                  </>
                ) : (
                  <>
                    <Play className="h-5 w-5" />
                    Start Scan
                  </>
                )}
              </Button>

              {isScanning && (
                <div className="text-center">
                  <div className="text-sm text-muted-foreground mb-2">Initializing security scan...</div>
                  <div className="flex items-center justify-center gap-2 font-mono text-xs text-primary">
                    <div className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
                    <span>Starting {scanTypes.find((s) => s.id === selectedScan)?.name}</span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
