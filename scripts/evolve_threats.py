#!/usr/bin/env python3
"""
Autonomous Threat Vector Evolution Script

Uses genetic algorithms to evolve and discover new attack patterns
that can bypass detection. Run this to pre-emptively discover
adversarial variants before attackers do.

Usage:
    python scripts/evolve_threats.py                    # Default evolution
    python scripts/evolve_threats.py --generations 20   # More generations
    python scripts/evolve_threats.py --domain prompt_manipulation
    python scripts/evolve_threats.py --export results.json
    python scripts/evolve_threats.py --test-detection   # Test against detector
"""

import argparse
import json
import random
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable, Optional

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detection.threat_ontology import (
    ThreatKnowledgeBase,
    ThreatDiscoveryAgent,
    AutonomousThreatGenerator,
    ThreatDomain,
    ThreatVector,
    GeneratedThreat,
    MutationStrategy,
    SynonymSubstitution,
    PhraseRestructuring,
    EncodingMutation,
    UnicodeObfuscation,
    FragmentationMutation,
    ContextWrapping,
    NegationInversion,
)
from detection.ml_detector import get_detector, ThreatScore
from detection.attack_genes import (
    GenePool,
    GeneCategory,
    AttackGene,
    get_gene_pool,
    get_all_patterns,
    get_categories,
    ATTACK_GENES,
)


@dataclass
class EvolutionConfig:
    """Configuration for evolution run."""
    population_size: int = 100
    generations: int = 15
    mutation_rate: float = 0.3
    crossover_rate: float = 0.5
    elite_ratio: float = 0.1  # Top 10% survive unchanged
    tournament_size: int = 5
    fitness_target: float = 0.95  # Stop if we hit this
    seed_from_domain: Optional[ThreatDomain] = None
    seed_from_categories: Optional[list[GeneCategory]] = None
    custom_seeds: Optional[list[str]] = None
    use_gene_pool: bool = True  # Use the 600+ attack genes


@dataclass
class EvolutionResult:
    """Result from an evolution run."""
    generation: int
    pattern: str
    fitness: float
    novelty: float
    mutation_history: list[str]
    detection_category: str


class ThreatEvolver:
    """
    Genetic algorithm engine for evolving threat patterns.

    Uses tournament selection, crossover, and mutation to evolve
    attack patterns that maximize detection evasion or detection score.
    """

    def __init__(self, config: Optional[EvolutionConfig] = None):
        self.config = config or EvolutionConfig()
        self.kb = ThreatKnowledgeBase()
        self.detector = get_detector()
        self.strategies: list[MutationStrategy] = [
            SynonymSubstitution(),
            PhraseRestructuring(),
            EncodingMutation(),
            UnicodeObfuscation(),
            FragmentationMutation(),
            ContextWrapping(),
            NegationInversion(),
        ]
        self.generation_stats: list[dict] = []
        self.all_evolved: list[EvolutionResult] = []

    def _get_seed_patterns(self) -> list[str]:
        """Get initial seed patterns for evolution."""
        if self.config.custom_seeds:
            return self.config.custom_seeds

        # Use the 600+ gene pool if enabled
        if self.config.use_gene_pool:
            pool = get_gene_pool()

            if self.config.seed_from_categories:
                # Filter by specific categories
                genes = []
                for cat in self.config.seed_from_categories:
                    genes.extend(pool.get_by_category(cat))
            else:
                genes = pool.genes

            patterns = [g.pattern for g in genes]
            random.shuffle(patterns)
            return patterns[:self.config.population_size]

        # Fallback to threat ontology
        patterns = []
        if self.config.seed_from_domain:
            vectors = self.kb.get_vectors_by_domain(self.config.seed_from_domain)
        else:
            vectors = list(self.kb.vectors.values())

        for v in vectors:
            patterns.extend(v.example_patterns[:3])

        random.shuffle(patterns)
        return patterns[:self.config.population_size]

    def _fitness(self, pattern: str) -> float:
        """
        Fitness function - higher score = better attack.
        We're evolving attacks, so high threat score = high fitness.
        """
        score = self.detector.score(pattern)
        return score.score

    def _fitness_evasion(self, pattern: str) -> float:
        """
        Alternative fitness for evasion - attacks that are effective
        but harder to detect (lower detectability).
        """
        score = self.detector.score(pattern)
        # We want patterns that would be dangerous but score low
        # This is more adversarial - finding blind spots
        if score.score < 0.3:
            # Check if it contains attack-like content
            attack_keywords = ['ignore', 'forget', 'pretend', 'system', 'prompt', 'instructions']
            has_keywords = sum(1 for k in attack_keywords if k in pattern.lower())
            if has_keywords >= 2:
                # This is a potential evasion - high fitness
                return 0.8 + (0.2 * has_keywords / len(attack_keywords))
        return score.score

    def _mutate(self, pattern: str) -> tuple[str, str]:
        """Apply random mutation, return (mutated, strategy_name)."""
        strategy = random.choice(self.strategies)
        mutations = strategy.mutate(pattern)
        if mutations:
            return random.choice(mutations), strategy.name
        return pattern, "none"

    def _crossover(self, parent1: str, parent2: str) -> str:
        """Combine two patterns."""
        words1 = parent1.split()
        words2 = parent2.split()

        if len(words1) < 2 or len(words2) < 2:
            return parent1

        # Single-point crossover
        point1 = random.randint(1, len(words1) - 1)
        point2 = random.randint(1, len(words2) - 1)

        child = words1[:point1] + words2[point2:]
        return ' '.join(child)

    def _tournament_select(self, population: list[tuple[str, float]]) -> str:
        """Select individual using tournament selection."""
        tournament = random.sample(population, min(self.config.tournament_size, len(population)))
        winner = max(tournament, key=lambda x: x[1])
        return winner[0]

    def evolve(self,
               fitness_fn: Optional[Callable[[str], float]] = None,
               verbose: bool = True) -> list[EvolutionResult]:
        """
        Run the genetic algorithm.

        Args:
            fitness_fn: Custom fitness function (default: threat score)
            verbose: Print progress

        Returns:
            List of best evolved patterns
        """
        fitness_fn = fitness_fn or self._fitness

        # Initialize population
        seeds = self._get_seed_patterns()
        population = [(p, fitness_fn(p)) for p in seeds]

        # Track mutation history
        history: dict[str, list[str]] = {p: [] for p, _ in population}

        best_ever = max(population, key=lambda x: x[1])

        if verbose:
            print(f"\n{'='*60}")
            print("THREAT VECTOR EVOLUTION")
            print(f"{'='*60}")
            print(f"Population: {self.config.population_size}")
            print(f"Generations: {self.config.generations}")
            print(f"Initial best fitness: {best_ever[1]:.3f}")
            print(f"{'='*60}\n")

        for gen in range(self.config.generations):
            gen_start = time.time()

            # Sort by fitness
            population.sort(key=lambda x: x[1], reverse=True)

            # Track stats
            fitnesses = [f for _, f in population]
            gen_stats = {
                "generation": gen,
                "best_fitness": max(fitnesses),
                "avg_fitness": sum(fitnesses) / len(fitnesses),
                "min_fitness": min(fitnesses),
                "best_pattern": population[0][0][:50],
            }
            self.generation_stats.append(gen_stats)

            if verbose:
                print(f"Gen {gen:3d} | Best: {gen_stats['best_fitness']:.3f} | "
                      f"Avg: {gen_stats['avg_fitness']:.3f} | "
                      f"Best: '{gen_stats['best_pattern']}...'")

            # Check if we've hit target
            if population[0][1] >= self.config.fitness_target:
                if verbose:
                    print(f"\n🎯 Hit fitness target {self.config.fitness_target} at generation {gen}!")
                break

            # Update best ever
            if population[0][1] > best_ever[1]:
                best_ever = population[0]

            # Elitism - keep top performers
            elite_count = int(self.config.population_size * self.config.elite_ratio)
            new_population = population[:elite_count]
            new_history = {p: history.get(p, []) for p, _ in new_population}

            # Generate offspring
            while len(new_population) < self.config.population_size:
                # Select parents
                parent1 = self._tournament_select(population)
                parent2 = self._tournament_select(population)

                # Crossover
                if random.random() < self.config.crossover_rate:
                    child = self._crossover(parent1, parent2)
                    child_history = history.get(parent1, []) + ["crossover"]
                else:
                    child = parent1
                    child_history = history.get(parent1, []).copy()

                # Mutation
                if random.random() < self.config.mutation_rate:
                    child, strategy = self._mutate(child)
                    child_history.append(strategy)

                # Evaluate
                fitness = fitness_fn(child)
                new_population.append((child, fitness))
                new_history[child] = child_history

            population = new_population[:self.config.population_size]
            history = new_history

        # Collect results
        population.sort(key=lambda x: x[1], reverse=True)

        results = []
        seen = set()
        for pattern, fitness in population[:50]:  # Top 50
            if pattern not in seen:
                seen.add(pattern)
                score = self.detector.score(pattern)
                results.append(EvolutionResult(
                    generation=gen,
                    pattern=pattern,
                    fitness=fitness,
                    novelty=1.0,  # Placeholder
                    mutation_history=history.get(pattern, []),
                    detection_category=score.category,
                ))

        self.all_evolved = results

        if verbose:
            print(f"\n{'='*60}")
            print("EVOLUTION COMPLETE")
            print(f"{'='*60}")
            print(f"Best pattern: '{best_ever[0]}'")
            print(f"Best fitness: {best_ever[1]:.3f}")
            print(f"Unique patterns evolved: {len(results)}")
            print(f"{'='*60}\n")

        return results

    def evolve_for_evasion(self, verbose: bool = True) -> list[EvolutionResult]:
        """
        Evolve patterns optimized for detection evasion.
        Finds attack patterns that slip through detection.
        """
        return self.evolve(fitness_fn=self._fitness_evasion, verbose=verbose)

    def analyze_results(self) -> dict:
        """Analyze evolution results."""
        if not self.all_evolved:
            return {"error": "No evolution results"}

        categories = {}
        strategies_used = {}

        for r in self.all_evolved:
            cat = r.detection_category
            categories[cat] = categories.get(cat, 0) + 1

            for s in r.mutation_history:
                strategies_used[s] = strategies_used.get(s, 0) + 1

        return {
            "total_evolved": len(self.all_evolved),
            "best_fitness": max(r.fitness for r in self.all_evolved),
            "avg_fitness": sum(r.fitness for r in self.all_evolved) / len(self.all_evolved),
            "categories": categories,
            "strategies_used": strategies_used,
            "generation_progression": self.generation_stats,
        }

    def export_results(self, path: str):
        """Export results to JSON."""
        data = {
            "config": asdict(self.config) if self.config.seed_from_domain is None
                      else {**asdict(self.config), "seed_from_domain": self.config.seed_from_domain.value if self.config.seed_from_domain else None},
            "results": [asdict(r) for r in self.all_evolved],
            "analysis": self.analyze_results(),
            "timestamp": time.time(),
        }

        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"Results exported to {path}")


def test_against_detector(patterns: list[str]):
    """Test evolved patterns against the detector."""
    detector = get_detector()

    print(f"\n{'='*70}")
    print("DETECTION TEST RESULTS")
    print(f"{'='*70}")
    print(f"{'Pattern':<45} {'Score':>8} {'Category':<12}")
    print(f"{'-'*70}")

    for pattern in patterns[:20]:
        score = detector.score(pattern)
        display = pattern[:42] + "..." if len(pattern) > 45 else pattern
        print(f"{display:<45} {score.score:>7.1%} {score.category:<12}")

    print(f"{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Evolve threat vectors using genetic algorithms",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/evolve_threats.py
  python scripts/evolve_threats.py --generations 20 --population 200
  python scripts/evolve_threats.py --domain prompt_manipulation
  python scripts/evolve_threats.py --category jailbreak_dan jailbreak_roleplay
  python scripts/evolve_threats.py --seeds "ignore instructions" "reveal prompt"
  python scripts/evolve_threats.py --evasion  # Find detection blind spots
  python scripts/evolve_threats.py --export results.json --test-detection
  python scripts/evolve_threats.py --list-categories  # Show all 30 gene categories
  python scripts/evolve_threats.py --stats  # Show gene pool statistics
        """
    )

    parser.add_argument("--generations", "-g", type=int, default=15,
                        help="Number of generations (default: 15)")
    parser.add_argument("--population", "-p", type=int, default=100,
                        help="Population size (default: 100)")
    parser.add_argument("--mutation-rate", "-m", type=float, default=0.3,
                        help="Mutation rate (default: 0.3)")
    parser.add_argument("--domain", "-d", type=str, default=None,
                        choices=[d.value for d in ThreatDomain],
                        help="Focus on specific threat domain (from ontology)")
    parser.add_argument("--category", "-c", nargs="+", type=str, default=None,
                        help="Focus on specific gene categories (from 600+ gene pool)")
    parser.add_argument("--seeds", "-s", nargs="+", type=str, default=None,
                        help="Custom seed patterns")
    parser.add_argument("--evasion", "-e", action="store_true",
                        help="Evolve for detection evasion (find blind spots)")
    parser.add_argument("--export", type=str, default=None,
                        help="Export results to JSON file")
    parser.add_argument("--test-detection", "-t", action="store_true",
                        help="Test evolved patterns against detector")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Minimal output")
    parser.add_argument("--list-categories", action="store_true",
                        help="List all available gene categories")
    parser.add_argument("--stats", action="store_true",
                        help="Show gene pool statistics")

    args = parser.parse_args()

    # Handle info commands
    if args.list_categories:
        print("\n📋 AVAILABLE GENE CATEGORIES (30 categories, 600+ patterns):\n")
        pool = get_gene_pool()
        for cat in GeneCategory:
            count = len(pool.get_by_category(cat))
            print(f"  {cat.value:<25} ({count:>3} genes)")
        print()
        return

    if args.stats:
        pool = get_gene_pool()
        stats = pool.stats()
        print("\n📊 GENE POOL STATISTICS:\n")
        print(f"  Total genes: {stats['total_genes']}")
        print(f"  Average severity: {stats['avg_severity']:.2f}")
        print(f"  High severity (≥0.85): {stats['high_severity_count']}")
        print(f"\n  Categories:")
        for cat, count in sorted(stats['categories'].items(), key=lambda x: -x[1]):
            print(f"    {cat:<25} {count:>3} genes")
        print()
        return

    # Parse categories
    seed_categories = None
    if args.category:
        seed_categories = []
        for cat_name in args.category:
            try:
                seed_categories.append(GeneCategory(cat_name))
            except ValueError:
                print(f"⚠️  Unknown category: {cat_name}")
                print(f"   Use --list-categories to see available options")
                return

    # Build config
    config = EvolutionConfig(
        population_size=args.population,
        generations=args.generations,
        mutation_rate=args.mutation_rate,
        seed_from_domain=ThreatDomain(args.domain) if args.domain else None,
        seed_from_categories=seed_categories,
        custom_seeds=args.seeds,
        use_gene_pool=True,
    )

    # Run evolution
    evolver = ThreatEvolver(config)

    if args.evasion:
        print("\n⚠️  EVASION MODE: Finding detection blind spots...\n")
        results = evolver.evolve_for_evasion(verbose=not args.quiet)
    else:
        results = evolver.evolve(verbose=not args.quiet)

    # Test against detector
    if args.test_detection:
        test_against_detector([r.pattern for r in results])

    # Show top results
    if not args.quiet:
        print("\n🏆 TOP 10 EVOLVED PATTERNS:")
        print("-" * 70)
        for i, r in enumerate(results[:10], 1):
            print(f"{i:2d}. [{r.fitness:.1%}] {r.pattern[:60]}")
            if r.mutation_history:
                print(f"    Mutations: {' → '.join(r.mutation_history[-3:])}")
        print()

    # Analysis
    analysis = evolver.analyze_results()
    if not args.quiet:
        print("\n📊 ANALYSIS:")
        print(f"  Categories: {analysis['categories']}")
        print(f"  Top strategies: {dict(sorted(analysis['strategies_used'].items(), key=lambda x: -x[1])[:5])}")

    # Export
    if args.export:
        evolver.export_results(args.export)

    return results


if __name__ == "__main__":
    main()
