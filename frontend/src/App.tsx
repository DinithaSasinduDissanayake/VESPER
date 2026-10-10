import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'

const components = [
  { id: 'A', name: 'Text risk', output: 'Risk score from the CVE description' },
  { id: 'B', name: 'Exploit timing', output: 'How soon exploitation is likely' },
  { id: 'C', name: 'Knowledge graph', output: 'Graph-based risk score' },
  { id: 'D', name: 'Fusion', output: 'Combined ranking and patch schedule' },
]

function App() {
  return (
    <main className="mx-auto flex min-h-svh max-w-4xl flex-col gap-8 p-8">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">VESPER</h1>
          <p className="text-muted-foreground">
            Machine-learning-based prioritisation of software vulnerabilities
          </p>
        </div>
        <Button variant="outline" asChild>
          <a href="https://github.com/DinithaSasinduDissanayake/VESPER">Repository</a>
        </Button>
      </header>

      <section className="grid gap-4 sm:grid-cols-2">
        {components.map((component) => (
          <Card key={component.id}>
            <CardHeader>
              <CardTitle>Component {component.id}</CardTitle>
              <CardDescription>{component.name}</CardDescription>
            </CardHeader>
            <CardContent>{component.output}</CardContent>
          </Card>
        ))}
      </section>
    </main>
  )
}

export default App
