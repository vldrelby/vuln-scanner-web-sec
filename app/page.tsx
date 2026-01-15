import Link from "next/link"
import { Shield, Zap, Lock, ArrowRight, Terminal, Search, FileCode } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Navbar } from "@/components/navbar"

export default function HomePage() {
  const features = [
    {
      icon: Terminal,
      title: "Nmap Scanning",
      description: "Comprehensive network discovery and security auditing with industry-standard Nmap integration.",
    },
    {
      icon: Search,
      title: "Nuclei Scanner",
      description: "Fast and customizable vulnerability scanner powered by community-driven templates.",
    },
    {
      icon: FileCode,
      title: "Custom Scans",
      description: "Define your own scanning logic and parameters for specialized security assessments.",
    },
  ]

  return (
    <div className="min-h-screen">
      <Navbar />

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 overflow-hidden">
        <div className="absolute inset-0 grid-background" />
        <div className="absolute inset-0 bg-gradient-to-b from-primary/5 via-transparent to-transparent" />

        <div className="container relative mx-auto px-4">
          <div className="max-w-4xl mx-auto text-center">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-6 animate-in fade-in slide-in-from-bottom-4 duration-700">
              <Shield className="h-4 w-4 text-primary" />
              <span className="text-sm font-mono text-primary">Enterprise Security Platform</span>
            </div>

            <h1 className="text-5xl md:text-7xl font-bold mb-6 animate-in fade-in slide-in-from-bottom-6 duration-700 delay-100 text-balance">
              Advanced Vulnerability{" "}
              <span className="bg-gradient-to-r from-primary via-accent to-primary bg-clip-text text-transparent">
                Scanner
              </span>
            </h1>

            <p className="text-xl text-muted-foreground mb-10 max-w-2xl mx-auto animate-in fade-in slide-in-from-bottom-8 duration-700 delay-200 text-pretty leading-relaxed">
              Identify security vulnerabilities across your infrastructure with automated scanning, real-time threat
              detection, and comprehensive reporting.
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 animate-in fade-in slide-in-from-bottom-10 duration-700 delay-300">
              <Button asChild size="lg" className="gap-2 font-semibold">
                <Link href="/scan">
                  Start Scanning
                  <ArrowRight className="h-4 w-4" />
                </Link>
              </Button>
              <Button asChild variant="outline" size="lg" className="gap-2 bg-transparent">
                <Link href="/results">View Reports</Link>
              </Button>
            </div>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-16 border-y border-border/40">
        <div className="container mx-auto px-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            {[
              { value: "99.9%", label: "Vulnerability Detection Rate" },
              { value: "<5min", label: "Average Scan Time" },
              { value: "24/7", label: "Continuous Monitoring" },
            ].map((stat, i) => (
              <div key={i} className="text-center">
                <div className="text-4xl font-bold font-mono text-primary mb-2">{stat.value}</div>
                <div className="text-sm text-muted-foreground">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20">
        <div className="container mx-auto px-4">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">Powerful Scanning Engines</h2>
            <p className="text-muted-foreground max-w-2xl mx-auto text-pretty leading-relaxed">
              Leverage industry-leading security tools and custom scanning capabilities to protect your digital assets.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-6xl mx-auto">
            {features.map((feature, i) => (
              <Card
                key={i}
                className="p-6 bg-card border-border/40 hover:border-primary/50 transition-all duration-300 hover:shadow-lg hover:shadow-primary/5"
              >
                <div className="rounded-lg bg-primary/10 w-12 h-12 flex items-center justify-center mb-4">
                  <feature.icon className="h-6 w-6 text-primary" />
                </div>
                <h3 className="text-xl font-semibold mb-2">{feature.title}</h3>
                <p className="text-muted-foreground leading-relaxed">{feature.description}</p>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Security Features */}
      <section className="py-20 bg-secondary/20">
        <div className="container mx-auto px-4">
          <div className="grid md:grid-cols-2 gap-12 max-w-6xl mx-auto items-center">
            <div>
              <h2 className="text-3xl md:text-4xl font-bold mb-6 text-balance">Enterprise-Grade Security Analysis</h2>
              <div className="space-y-4">
                {[
                  { icon: Zap, text: "Real-time vulnerability detection and alerts" },
                  { icon: Lock, text: "Encrypted data transmission and storage" },
                  { icon: Shield, text: "Compliance with security standards" },
                ].map((item, i) => (
                  <div key={i} className="flex items-start gap-3">
                    <div className="rounded-md bg-primary/10 p-2 mt-0.5">
                      <item.icon className="h-4 w-4 text-primary" />
                    </div>
                    <p className="text-muted-foreground leading-relaxed">{item.text}</p>
                  </div>
                ))}
              </div>
            </div>

            <Card className="p-8 bg-gradient-to-br from-card to-secondary/20 border-border/40">
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-mono text-muted-foreground">system.status</span>
                  <span className="text-xs px-2 py-1 rounded-full bg-accent/20 text-accent font-mono">ACTIVE</span>
                </div>
                <div className="space-y-3">
                  {["Network Scanner", "Vulnerability Engine", "Threat Detection"].map((item, i) => (
                    <div key={i} className="flex items-center gap-3">
                      <div className="h-2 w-2 rounded-full bg-accent animate-pulse" />
                      <span className="text-sm font-mono">{item}</span>
                    </div>
                  ))}
                </div>
              </div>
            </Card>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20">
        <div className="container mx-auto px-4">
          <Card className="max-w-4xl mx-auto p-12 text-center bg-gradient-to-br from-primary/10 via-accent/5 to-primary/5 border-primary/20">
            <h2 className="text-3xl md:text-4xl font-bold mb-4 text-balance">Ready to Secure Your Infrastructure?</h2>
            <p className="text-muted-foreground mb-8 max-w-2xl mx-auto text-pretty leading-relaxed">
              Start scanning for vulnerabilities today and protect your digital assets from potential security threats.
            </p>
            <Button asChild size="lg" className="gap-2">
              <Link href="/scan">
                Launch Scanner
                <ArrowRight className="h-4 w-4" />
              </Link>
            </Button>
          </Card>
        </div>
      </section>
    </div>
  )
}
