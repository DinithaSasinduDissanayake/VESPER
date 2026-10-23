import { Component, type ErrorInfo, type ReactNode } from 'react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'

type Props = { children: ReactNode }
type State = { error: Error | null }

// Keeps a render error inside one page so the sidebar and other pages still work.
export class PageErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Page render failed', error, info.componentStack)
  }

  render() {
    if (!this.state.error) return this.props.children
    return (
      <Alert variant="destructive" className="mx-auto max-w-3xl">
        <AlertTitle>This page failed to render.</AlertTitle>
        <AlertDescription className="flex flex-col items-start gap-3">
          <span>{this.state.error.message}</span>
          <Button variant="outline" onClick={() => this.setState({ error: null })}>Try again</Button>
        </AlertDescription>
      </Alert>
    )
  }
}
