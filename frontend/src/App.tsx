import { useEffect, useState, type ComponentType } from 'react'
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
  // CVE to open when the queue is reached from the Home top list.
  const [openCveId, setOpenCveId] = useState<string | null>(null)
  // Sidebar links and the logo all just switch the page.
  const goTo = (id: PageId) => {
    setOpenCveId(null)
    setActiveId(id)
  }
  const openCve = (cveId: string) => {
    setOpenCveId(cveId)
    setActiveId('queue')
  }
  // Load the text model on the backend while the user is still on another page.
  useEffect(warmUpTextModel, [])

  return (
    <div className="flex min-h-svh flex-col bg-surface md:flex-row">
      {/* The wrapper stretches to the page height so the sidebar colour does not stop at the first screen. */}
      <div className="w-full shrink-0 border-b bg-sidebar md:w-64 md:border-r md:border-b-0">
      <aside className="flex w-full flex-col text-sidebar-foreground md:sticky md:top-0 md:h-svh">
        <button
          type="button"
          onClick={() => goTo('home')}
          className="flex items-center gap-3 px-4 py-5 text-left outline-none focus-visible:ring-3 focus-visible:ring-sidebar-ring/50"
        >
          <span aria-hidden="true" className="grid size-9 shrink-0 place-items-center rounded-lg bg-primary text-base font-bold text-primary-foreground">
            V
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

      </aside>
      </div>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-14 items-center gap-3 border-b bg-background/85 px-4 backdrop-blur sm:px-6">
          <h1 className="text-base font-semibold tracking-tight">{page.title}</h1>
        </header>

        {/* key resets the page's state (e.g. the open CVE) when the page changes. */}
        <main className="min-w-0 flex-1 p-4 text-base sm:p-6 lg:p-8">
          <PageErrorBoundary key={activeId}>
            {activeId === 'home' ? (
              <HomePage key={activeId} onNavigate={goTo} onOpenCve={openCve} />
            ) : activeId === 'queue' ? (
              <QueuePage key={activeId} initialCveId={openCveId} />
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
