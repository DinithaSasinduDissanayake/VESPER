import { useEffect, useState, type ComponentType } from 'react'
import { ShieldCheck } from 'lucide-react'
import { AnalysePage } from '@/analyse/AnalysePage'
import { warmUpTextModel } from '@/api/aText'
import { PageErrorBoundary } from '@/components/PageErrorBoundary'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { mainNav, pages, type PageId } from '@/pages'
import { ExposurePage } from '@/exposure/ExposurePage'
import { HomePage } from '@/home/HomePage'
import { SprintPlanPage } from '@/plan/SprintPlanPage'
import { QueuePage } from '@/queue/QueuePage'
import { ScoresPage } from '@/scores/ScoresPage'
import { TimingPage } from '@/timing/TimingPage'

// The component that draws each page.
const pageComponents: Record<Exclude<PageId, 'home'>, ComponentType> = {
  queue: QueuePage,
  timing: TimingPage,
  exposure: ExposurePage,
  sprint: SprintPlanPage,
  analyse: AnalysePage,
  scores: ScoresPage,
}

// Icon colour for the active page: the evidence stream each page belongs to.
const streamIcon: Record<PageId, string> = {
  home: 'text-primary',
  queue: 'text-stream-ranking',
  timing: 'text-stream-timing',
  exposure: 'text-stream-structure',
  sprint: 'text-stream-ranking',
  analyse: 'text-stream-text',
  scores: 'text-primary',
}

type NavItemProps = {
  id: PageId
  activeId: PageId
  onSelect: (id: PageId) => void
  className?: string
}

// One sidebar link. Used for the main menu and the footer link.
function NavItem({ id, activeId, onSelect, className }: NavItemProps) {
  const { title, icon: Icon } = pages[id]
  const isActive = id === activeId
  return (
    <Button
      variant="ghost"
      size="lg"
      aria-current={isActive ? 'page' : undefined}
      onClick={() => onSelect(id)}
      className={cn(
        'h-10 justify-start gap-3 px-3 text-base text-sidebar-foreground/80 transition-colors hover:bg-sidebar-accent/70 hover:text-sidebar-foreground [&_svg:not([class*=size-])]:size-5',
        isActive && 'bg-sidebar-accent font-medium text-sidebar-accent-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
        className,
      )}
    >
      {Icon && (
        <Icon
          className={cn(
            'transition-colors',
            isActive ? streamIcon[id] : 'text-muted-foreground group-hover/button:text-sidebar-foreground',
          )}
        />
      )}
      {title}
    </Button>
  )
}

function App() {
  const [activeId, setActiveId] = useState<PageId>('home')
  const page = pages[activeId]
  const PageComponent = activeId === 'home' ? null : pageComponents[activeId]
  // Sidebar links and the logo all just switch the page.
  const goTo = setActiveId
  // Load the text model on the backend while the user is still on another page.
  useEffect(warmUpTextModel, [])

  return (
    <div className="flex min-h-svh flex-col bg-surface md:flex-row">
      <aside className="flex w-full shrink-0 flex-col border-b bg-sidebar text-sidebar-foreground md:sticky md:top-0 md:h-svh md:w-64 md:border-r md:border-b-0">
        <button
          type="button"
          onClick={() => goTo('home')}
          className="flex items-center gap-3 px-4 py-5 text-left outline-none focus-visible:ring-3 focus-visible:ring-sidebar-ring/50"
        >
          <span className="grid size-9 place-items-center rounded-xl bg-linear-135 from-primary to-stream-ranking text-primary-foreground shadow-sm ring-1 ring-primary/20">
            <ShieldCheck className="size-5" />
          </span>
          <span className="flex flex-col">
            <span className="text-base font-semibold tracking-tight">VESPER</span>
            <span className="text-sm text-muted-foreground">Vulnerability evidence workbench</span>
          </span>
        </button>

        <nav aria-label="Main" className="flex flex-1 flex-wrap gap-1 p-3 md:flex-col md:flex-nowrap">
          {mainNav.map((id) => (
            <NavItem key={id} id={id} activeId={activeId} onSelect={goTo} />
          ))}
        </nav>

        <nav aria-label="Help" className="flex flex-col border-t p-3">
          <NavItem
            id="scores"
            activeId={activeId}
            onSelect={goTo}
            className="text-muted-foreground"
          />
        </nav>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-14 items-center gap-3 border-b bg-background/85 px-4 backdrop-blur sm:px-6">
          {page.icon && (
            <span className="grid size-8 place-items-center rounded-lg bg-accent text-accent-foreground">
              <page.icon className="size-4" />
            </span>
          )}
          <h1 className="text-base font-semibold tracking-tight">{page.title}</h1>
        </header>

        {/* key resets the page's state (e.g. the open CVE) when the page changes. */}
        <main className="min-w-0 flex-1 p-4 text-base sm:p-6 lg:p-8">
          <PageErrorBoundary key={activeId}>
            {activeId === 'home' ? (
              <HomePage key={activeId} onNavigate={goTo} />
            ) : (
              PageComponent && <PageComponent key={activeId} />
            )}
          </PageErrorBoundary>
        </main>
      </div>
    </div>
  )
}

export default App
