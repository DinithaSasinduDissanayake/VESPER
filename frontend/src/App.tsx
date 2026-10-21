import { useState, type ComponentType } from 'react'
import { AnalysePage } from '@/analyse/AnalysePage'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { mainNav, pages, type PageId } from '@/pages'
import { ExposurePage } from '@/exposure/ExposurePage'
import { SprintPlanPage } from '@/plan/SprintPlanPage'
import { QueuePage } from '@/queue/QueuePage'
import { ScoresPage } from '@/scores/ScoresPage'

// The component that draws each page.
const pageComponents: Record<PageId, ComponentType> = {
  queue: QueuePage,
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
      className={cn('justify-start', isActive && 'bg-sidebar-accent', className)}
    >
      {Icon && <Icon />}
      {title}
    </Button>
  )
}

function App() {
  const [activeId, setActiveId] = useState<PageId>('queue')
  const page = pages[activeId]
  const PageComponent = pageComponents[activeId]
  // Sidebar links and the logo all just switch the page.
  const goTo = setActiveId

  return (
    <div className="flex min-h-svh flex-col md:flex-row">
      <aside className="flex w-full shrink-0 flex-col border-b bg-sidebar md:w-64 md:border-r md:border-b-0">
        <button
          type="button"
          onClick={() => goTo('queue')}
          className="border-b px-4 py-3 text-left"
        >
          <span className="block font-semibold">VESPER</span>
          <span className="block text-xs text-muted-foreground">
            Vulnerability Evidence Workbench
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
            className="text-xs text-muted-foreground"
          />
        </nav>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 items-center justify-between border-b px-6">
          <h1 className="text-sm font-semibold">{page.title}</h1>
          <span className="text-sm text-muted-foreground">Data snapshot: —</span>
        </header>

        {/* key resets the page's state (e.g. the open CVE) when the page changes. */}
        <main className="min-w-0 p-3 text-sm sm:p-6">
          <PageComponent key={activeId} />
        </main>
      </div>
    </div>
  )
}

export default App
