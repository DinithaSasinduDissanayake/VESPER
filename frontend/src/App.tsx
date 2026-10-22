import { useState, type ComponentType } from 'react'
import { ShieldCheck } from 'lucide-react'
import { AnalysePage } from '@/analyse/AnalysePage'
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
      size="sm"
      aria-current={isActive ? 'page' : undefined}
      onClick={() => onSelect(id)}
      className={cn(
        'justify-start text-sidebar-foreground/80 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
        isActive && 'bg-sidebar-accent font-medium text-sidebar-accent-foreground',
        className,
      )}
    >
      {Icon && <Icon />}
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

  return (
    <div className="flex min-h-svh flex-col bg-background md:flex-row">
      <aside className="flex w-full shrink-0 flex-col border-b bg-sidebar text-sidebar-foreground md:sticky md:top-0 md:h-svh md:w-60 md:border-r md:border-b-0">
        <button
          type="button"
          onClick={() => goTo('home')}
          className="flex items-center gap-2.5 px-4 py-4 text-left outline-none focus-visible:ring-3 focus-visible:ring-sidebar-ring/50"
        >
          <span className="grid size-8 place-items-center rounded-lg bg-sidebar-primary text-sidebar-primary-foreground">
            <ShieldCheck className="size-4" />
          </span>
          <span className="flex flex-col">
            <span className="text-sm font-semibold">VESPER</span>
            <span className="text-xs text-muted-foreground">Vulnerability evidence workbench</span>
          </span>
        </button>

        <nav aria-label="Main" className="flex flex-1 flex-wrap gap-1 p-2 md:flex-col md:flex-nowrap">
          {mainNav.map((id) => (
            <NavItem key={id} id={id} activeId={activeId} onSelect={goTo} />
          ))}
        </nav>

        <nav aria-label="Help" className="flex flex-col border-t p-2">
          <NavItem
            id="scores"
            activeId={activeId}
            onSelect={goTo}
            className="text-muted-foreground"
          />
        </nav>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-14 items-center border-b bg-background/95 px-4 backdrop-blur sm:px-6">
          <h1 className="text-sm font-medium">{page.title}</h1>
        </header>

        {/* key resets the page's state (e.g. the open CVE) when the page changes. */}
        <main className="min-w-0 flex-1 p-4 text-sm sm:p-6">
          {activeId === 'home' ? (
            <HomePage key={activeId} onNavigate={goTo} />
          ) : (
            PageComponent && <PageComponent key={activeId} />
          )}
        </main>
      </div>
    </div>
  )
}

export default App
