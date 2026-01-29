"""
MaxDiff Survey Logic - BIBD Generation and Scoring

Implements Balanced Incomplete Block Design (BIBD) for MaxDiff surveys
and Best-Worst Counting scoring method.
"""

import random
from collections import defaultdict


def generate_sets(item_ids, sets_count, items_per_set):
    """
    Generate balanced sets for MaxDiff survey using greedy algorithm.

    Args:
        item_ids: List of item IDs to include in sets
        sets_count: Number of sets to generate
        items_per_set: Number of items in each set (3-5)

    Returns:
        List of sets, where each set is a list of item IDs
    """
    if len(item_ids) < items_per_set:
        raise ValueError(f"Need at least {items_per_set} items, got {len(item_ids)}")

    n_items = len(item_ids)
    total_slots = sets_count * items_per_set
    target_appearances = total_slots / n_items

    # Track appearances per item
    appearances = defaultdict(int)

    # Track co-occurrences to promote diversity
    co_occurrences = defaultdict(lambda: defaultdict(int))

    sets = []

    for _ in range(sets_count):
        # Score each item based on how far below target it is
        scores = {}
        for item_id in item_ids:
            # Higher score = more need to appear
            score = target_appearances - appearances[item_id]
            # Add small random factor for variety
            score += random.uniform(0, 0.5)
            scores[item_id] = score

        # Sort items by score (highest first)
        sorted_items = sorted(item_ids, key=lambda x: scores[x], reverse=True)

        # Select items for this set
        selected = []
        for item_id in sorted_items:
            if len(selected) >= items_per_set:
                break

            # Check co-occurrence penalty
            co_penalty = sum(co_occurrences[item_id][s] for s in selected)

            # Accept if no better option or penalty is low
            if co_penalty < 2 or len(selected) < items_per_set - 1:
                selected.append(item_id)

        # If we didn't get enough items, fill randomly
        while len(selected) < items_per_set:
            remaining = [i for i in item_ids if i not in selected]
            if remaining:
                selected.append(random.choice(remaining))
            else:
                break

        # Update tracking
        for item_id in selected:
            appearances[item_id] += 1
            for other_id in selected:
                if item_id != other_id:
                    co_occurrences[item_id][other_id] += 1

        # Shuffle to randomize position within set
        random.shuffle(selected)
        sets.append(selected)

    return sets


def calculate_scores(study_items, answers):
    """
    Calculate MaxDiff scores using Best-Worst Counting method.

    Args:
        study_items: List of Item objects from the study
        answers: List of Answer objects from all responses

    Returns:
        Dict with item_id as key and score data as value:
        {
            item_id: {
                'text': str,
                'best_count': int,
                'worst_count': int,
                'appearances': int,
                'raw_score': int,  # best - worst
                'normalized_score': float  # 0-100 scale
            }
        }
    """
    # Initialize scores
    scores = {}
    for item in study_items:
        scores[item.id] = {
            'text': item.text,
            'best_count': 0,
            'worst_count': 0,
            'appearances': 0,
            'raw_score': 0,
            'normalized_score': 0
        }

    # Count best/worst selections
    for answer in answers:
        item_ids = answer.item_ids

        # Count appearances
        for item_id in item_ids:
            if item_id in scores:
                scores[item_id]['appearances'] += 1

        # Count best selection
        if answer.best_item_id in scores:
            scores[answer.best_item_id]['best_count'] += 1

        # Count worst selection
        if answer.worst_item_id in scores:
            scores[answer.worst_item_id]['worst_count'] += 1

    # Calculate raw scores
    for item_id, data in scores.items():
        data['raw_score'] = data['best_count'] - data['worst_count']

    # Normalize to 0-100 scale
    raw_scores = [d['raw_score'] for d in scores.values()]
    if raw_scores:
        min_score = min(raw_scores)
        max_score = max(raw_scores)
        score_range = max_score - min_score

        for item_id, data in scores.items():
            if score_range > 0:
                data['normalized_score'] = round(
                    ((data['raw_score'] - min_score) / score_range) * 100, 1
                )
            else:
                data['normalized_score'] = 50.0  # All scores equal

    return scores


def get_ranked_items(scores):
    """
    Get items ranked by normalized score (highest first).

    Args:
        scores: Dict from calculate_scores()

    Returns:
        List of (item_id, score_data) tuples sorted by normalized_score descending
    """
    return sorted(
        scores.items(),
        key=lambda x: x[1]['normalized_score'],
        reverse=True
    )


def get_response_statistics(responses):
    """
    Calculate response statistics for a study.

    Args:
        responses: List of Response objects

    Returns:
        Dict with statistics
    """
    total = len(responses)
    completed = sum(1 for r in responses if r.completed_at is not None)
    in_progress = total - completed

    return {
        'total_responses': total,
        'completed_responses': completed,
        'in_progress_responses': in_progress,
        'completion_rate': round((completed / total * 100), 1) if total > 0 else 0
    }
