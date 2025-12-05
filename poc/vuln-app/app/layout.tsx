export const metadata = {
  title: 'CVE-2025-55182 Vulnerable App',
  description: 'Educational PoC for CVE-2025-55182',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
